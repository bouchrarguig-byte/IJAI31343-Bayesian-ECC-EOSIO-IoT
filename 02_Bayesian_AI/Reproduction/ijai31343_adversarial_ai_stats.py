#!/usr/bin/env python3
"""IJ-AI 31343: offline adversarial-input simulation and policy statistics.

STRICT PROVENANCE: synthetic event streams are not hardware experiments, packet
attacks, detected intrusions, energy measurements, or independent field data.
Existing Stage4/Stage6/Stage7 files and firmware are NEVER modified.

Runs the ACTUAL Stage7 intelligent_key_renewal.BayesianRiskEstimator for posterior
updates and cross-checks the actual AdaptiveRotationPolicy at representative
states. Fixed and heuristic comparators are transparently simulated.
Standard library only; matplotlib is optional for creating figures.
"""
from __future__ import annotations

import argparse
import csv
from collections import deque
from functools import lru_cache
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import random
import statistics as st
import sys
from datetime import datetime, timezone

SCENARIOS = (
    'benign', 'burst_invalid_proofs', 'step_rise', 'gradual_ramp',
    'attack_then_recovery', 'forged_alarm_flood',
)
POLICIES = (
    'fixed60', 'fixed90', 'fixed120', 'heuristic_2of5',
    'bayes_upper_lambda2', 'bayes_upper_lambda4', 'bayes_upper_lambda8',
    'bayes_mean_lambda4', 'bayes_window20_lambda4',
    'bayes_prior_1_9_lambda4', 'bayes_prior_1_49_lambda4',
)
BASE_SEED = 31343
_CACHED_SOURCE_MODEL = None

@lru_cache(maxsize=120000)
def posterior_cached(prior_a: int, prior_b: int, n_ok: int, n_bad: int, draws: int):
    """Cache identical posterior states across policies, scenarios and seeds.
    This only accelerates OFFLINE experiments; it does NOT change gateway code.
    """
    model = mk_model(_CACHED_SOURCE_MODEL, prior_a, prior_b, n_ok, n_bad, draws)
    return model.posterior_upper_bound(), model.posterior_mean

MIN_INTERVAL = 10.0
HORIZON = 600.0  # stipulated scenario only, not time-to-break


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(2**20), b''):
            h.update(chunk)
    return h.hexdigest()


def import_module(path: Path):
    spec = importlib.util.spec_from_file_location('stage7_policy_for_adversarial_study', path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'Cannot load policy from {path}')
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


def simulate_labels(scenario: str, seed: int, length: int) -> list[str]:
    """Create exogenous synthetic observations, identical for every policy.

    Labels are model inputs, not verified attack success or compromise labels.
    Each event is an abstract authentication feedback observation.
    """
    rng = random.Random(seed)
    events = []
    for i in range(length):
        rel = i / max(length - 1, 1)
        if scenario == 'benign':
            p = .01
        elif scenario == 'burst_invalid_proofs':
            # Two short deterministic bursts, with low-rate background noise.
            p = 1.0 if length // 3 <= i < length // 3 + 6 or 2 * length // 3 <= i < 2 * length // 3 + 6 else .01
        elif scenario == 'step_rise':
            p = .45 if length // 3 <= i < 2 * length // 3 else .01
        elif scenario == 'gradual_ramp':
            p = .01 + .49 * rel
        elif scenario == 'attack_then_recovery':
            p = .65 if length // 6 <= i < length // 2 else .01
        elif scenario == 'forged_alarm_flood':
            # Sensor/feedback alarm poisoning only; no physical/network exploit.
            p = 1.0 if length // 3 <= i < 2 * length // 3 else .01
        else:
            raise ValueError(scenario)
        events.append('invalid_proof' if rng.random() < p else 'success')
    return events


def mk_model(mod, prior_a: int, prior_b: int, successes: int,
             suspicious: int, n_draws: int):
    cfg = mod.PolicyConfig(prior_alpha=prior_a, prior_beta=prior_b,
                           posterior_samples=n_draws, seed=BASE_SEED)
    model = mod.BayesianRiskEstimator(cfg)
    model.normal_events = successes
    model.anomalies = suspicious
    return model


def policy_interval(risk: float, lam: float) -> float:
    interval = min(300., .7 * HORIZON, 120. / (1 + lam * risk))
    if not (MIN_INTERVAL <= interval < HORIZON):
        raise RuntimeError(f'Invalid interval {interval} with risk={risk}, lambda={lam}')
    return round(interval, 6)


def run_tests(mod) -> list[dict]:
    tests = []
    def test(name, run):
        try:
            run()
        except Exception as e:
            tests.append({'test': name, 'result': 'FAIL', 'reason': str(e)})
        else:
            tests.append({'test': name, 'result': 'PASS'})

    def must_raise(exc_type, fun):
        try:
            fun()
        except exc_type:
            return
        except Exception as e:
            raise AssertionError(f'Raised {type(e).__name__}, expected {exc_type.__name__}') from e
        raise AssertionError(f'Expected {exc_type.__name__} not raised')

    cfg = mod.PolicyConfig(posterior_samples=1024)
    def no_horizon():
        for v in (None, float('nan'), 0, -2):
            m = mod.BayesianRiskEstimator(cfg)
            p = mod.AdaptiveRotationPolicy(cfg, m)
            must_raise(mod.UnsafePolicyError, lambda: p.select_interval(v))

    def short_horizon():
        m = mod.BayesianRiskEstimator(cfg)
        p = mod.AdaptiveRotationPolicy(cfg, m)
        must_raise(mod.UnsafePolicyError, lambda: p.select_interval(9))

    def expires_and_blocks():
        m = mod.BayesianRiskEstimator(cfg)
        p = mod.AdaptiveRotationPolicy(cfg, m)
        monitor = mod.EpochMonitor(p, epoch_started_at=0)
        t = p.select_interval(HORIZON)['interval_seconds']
        assert monitor.state(0, HORIZON)['old_key_usable']
        assert monitor.state(t + .01, HORIZON)['state'] == 'REKEY_REQUIRED_BLOCK_OLD_KEY'

    def no_unverified_rotation():
        m = mod.BayesianRiskEstimator(cfg)
        monitor = mod.EpochMonitor(mod.AdaptiveRotationPolicy(cfg, m), epoch_started_at=0)
        must_raise(ValueError, lambda: monitor.confirm_rotation(60, new_authenticated_key_installed=False))
        assert monitor.epoch == 0

    def clock_rollback():
        m = mod.BayesianRiskEstimator(cfg)
        monitor = mod.EpochMonitor(mod.AdaptiveRotationPolicy(cfg, m), epoch_started_at=5)
        must_raise(ValueError, lambda: monitor.state(4, HORIZON))

    def unsupported_feedback():
        m = mod.BayesianRiskEstimator(cfg)
        must_raise(ValueError, lambda: m.observe('attacker_controlled_unknown_event'))

    def malicious_alarm_flood_shortens_interval():
        m = mod.BayesianRiskEstimator(cfg)
        p = mod.AdaptiveRotationPolicy(cfg, m)
        for _ in range(40):
            m.observe('success')
        benign = p.select_interval(HORIZON)['interval_seconds']
        for _ in range(25):
            m.observe('invalid_proof')
        alarm = p.select_interval(HORIZON)['interval_seconds']
        assert alarm < benign, (benign, alarm)

    def extreme_risk_fails_closed():
        extreme = mod.PolicyConfig(risk_sensitivity=100., posterior_samples=1024)
        m = mod.BayesianRiskEstimator(extreme)
        for _ in range(20):
            m.observe('invalid_proof')
        must_raise(mod.UnsafePolicyError,
                   lambda: mod.AdaptiveRotationPolicy(extreme, m).select_interval(HORIZON))

    for name, func in (
        ('missing_or_invalid_horizon_fails_closed', no_horizon),
        ('too_short_horizon_fails_closed', short_horizon),
        ('expired_epoch_blocks_old_key', expires_and_blocks),
        ('unverified_rotation_rejected', no_unverified_rotation),
        ('clock_rollback_rejected', clock_rollback),
        ('unsupported_feedback_rejected', unsupported_feedback),
        ('forged_alarm_flood_causes_rotation_pressure', malicious_alarm_flood_shortens_interval),
        ('excessive_risk_fails_closed', extreme_risk_fails_closed),
    ):
        test(name, func)
    return tests


def evaluate_sequence(mod, events, draws=1024):
    """Return simulated controller decisions at each successive input event."""
    recent = deque(maxlen=5)
    pred_recent = deque(maxlen=20)
    n_ok = n_bad = 0
    data = []
    for idx, event in enumerate(events, start=1):
        # Prequential (one-step-ahead) prediction BEFORE learning this label.
        y = 0 if event == 'success' else 1
        pred_cumulative = (1 + n_bad)/(20 + n_bad + n_ok)
        pred_window20 = (1 + sum(pred_recent))/(20 + len(pred_recent))
        pred_constant = .05
        if event == 'success':
            n_ok += 1
        else:
            n_bad += 1
        recent.append(event)
        pred_recent.append(y)
        # Identical recorded feedback for all policies; only decisions differ.
        q = {}
        for prior in ((1,19), (1,9), (1,49)):
            q[prior] = posterior_cached(prior[0], prior[1], n_ok, n_bad, draws)
        upper, risk_mean = q[(1,19)]
        recent_bad = sum(pred_recent)
        window_upper, _ = posterior_cached(1,19,len(pred_recent)-recent_bad, recent_bad, draws)
        values = {
            'fixed60': 60., 'fixed90': 90., 'fixed120': 120.,
            'heuristic_2of5': 60. if sum(x != 'success' for x in recent) >= 2 else 120.,
            'bayes_upper_lambda2': policy_interval(upper, 2),
            'bayes_upper_lambda4': policy_interval(upper, 4),
            'bayes_upper_lambda8': policy_interval(upper, 8),
            'bayes_mean_lambda4': policy_interval(risk_mean, 4),
            'bayes_window20_lambda4': policy_interval(window_upper, 4),
            'bayes_prior_1_9_lambda4': policy_interval(q[(1,9)][0], 4),
            'bayes_prior_1_49_lambda4': policy_interval(q[(1,49)][0], 4),
        }
        # Verify the reconstruction against the ORIGINAL class at sampled states.
        if idx in (1, len(events)//2, len(events)):
            source_cfg = mod.PolicyConfig(posterior_samples=draws)
            source_est = mk_model(mod, 1, 19, n_ok, n_bad, draws)
            source_val = mod.AdaptiveRotationPolicy(source_cfg, source_est).select_interval(HORIZON)['interval_seconds']
            if abs(source_val - values['bayes_upper_lambda4']) > 1e-6:
                raise RuntimeError('Model-to-reimplementation mismatch')
        data.append({'step': idx, 'event_type': event, 'observed_suspicious': y,
                     'brier_cumulative':(pred_cumulative-y)**2,
                     'brier_window20':(pred_window20-y)**2,
                     'brier_constant0p05':(pred_constant-y)**2,
                     'normal_so_far': n_ok,
                     'suspicious_so_far': n_bad, 'posterior_mean': risk_mean,
                     'posterior_upper_mc': upper, **values})
    return data


def bootstrap_ci(sample, rng, boots=2000):
    """Bootstrap over independent SYNTHETIC replicate seeds, not snapshots."""
    sample = list(sample)
    if len(sample) < 2:
        return (None, None)
    n = len(sample)
    res = sorted(st.mean(sample[rng.randrange(n)] for _ in range(n))
                 for __ in range(boots))
    return (res[int(.025 * (boots - 1))], res[int(.975 * (boots - 1))])


def simple_stats(sample, rng):
    mean_ci = bootstrap_ci(sample, rng)
    return {'n_independent_synthetic_sequences': len(sample),
            'mean': st.mean(sample),
            'sd_across_sequences': st.stdev(sample) if len(sample) >= 2 else None,
            'bootstrap_95_low': mean_ci[0], 'bootstrap_95_high': mean_ci[1]}


def write_csv(path, rows, cols):
    with path.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def plotting(dest, step_timelines, real_replay):
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        return ['Matplotlib not installed; figures skipped (all CSV/JSON complete).']
    figs = []
    for name in ('step_rise','attack_then_recovery','forged_alarm_flood'):
        rows = step_timelines[name]
        fig, ax = plt.subplots(figsize=(8.3,3.5))
        xx = [r['step'] for r in rows]
        for policy, label in [('fixed120','Fixed 120'),
                              ('heuristic_2of5','Heuristic 2-of-5'),
                              ('bayes_upper_lambda4','Bayesian upper, lambda=4')]:
            ax.plot(xx, [r[policy] for r in rows], label=label, linewidth=1.5)
        indices = [r['step'] for r in rows if r['event_type'] != 'success']
        if indices:
            ax.scatter(indices, [9.5] * len(indices), marker='|', s=25,
                       color='black', label='Synthetic suspicious input')
        ax.set_xlabel('Synthetic observation index (not seconds)')
        ax.set_ylabel('Computed key lifetime (s)')
        ax.set_ylim(0, 145)
        ax.set_title(f'{name.replace("_", " ").title()} — synthetic policy decisions')
        ax.grid(alpha=.20)
        ax.legend(fontsize=8, loc='upper right')
        fig.tight_layout()
        out = dest/f'SYNTHETIC_{name}.png'
        fig.savefig(out, dpi=210)
        plt.close(fig)
        figs.append(out.name)
    if real_replay.is_file():
        with real_replay.open(encoding='utf-8', newline='') as f:
            rows = list(csv.DictReader(f))
        required = {'snapshot','source_event','fixed_120','heuristic_2of5', 'bayes_upper_lambda4'}
        if rows and required.issubset(rows[0]):
            fig, ax = plt.subplots(figsize=(8.3,3.5))
            xx = [int(r['snapshot']) for r in rows]
            for p, label in [('fixed_120','Fixed 120'),
                             ('heuristic_2of5','Heuristic 2-of-5'),
                             ('bayes_upper_lambda4','Bayesian upper, lambda=4')]:
                ax.plot(xx,[float(r[p]) for r in rows],marker='o',markersize=3,label=label)
            risk_ix = [int(r['snapshot']) for r in rows if r['source_event']=='risk_observation']
            if risk_ix:
                ax.scatter(risk_ix,[11]*len(risk_ix),marker='x',color='black',label='Logged invalid proof')
            ax.set_xlabel('Recorded Stage4 feedback snapshot')
            ax.set_ylabel('Replayed computed lifetime (s)')
            ax.set_ylim(0, 140)
            ax.set_title('Stage4 recorded feedback — OFFLINE replay, NOT hardware trial')
            ax.grid(alpha=.20)
            ax.legend(fontsize=8)
            fig.tight_layout()
            path = dest/'RECORDED_STAGE4_policy_replay.png'
            fig.savefig(path,dpi=210)
            plt.close(fig)
            figs.append(path.name)
    return figs


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, default=Path.home()/'IJAI_31343_Work')
    p.add_argument('--output', type=Path, help='Separate destination for simulated results')
    p.add_argument('--replicates', type=int, default=12)
    p.add_argument('--length', type=int, default=120)
    p.add_argument('--posterior-samples', type=int, default=1024)
    p.add_argument('--no-plots', action='store_true')
    args = p.parse_args()
    if not 3 <= args.replicates <= 200:
        p.error('--replicates must be between 3 and 200')
    if not 36 <= args.length <= 1000:
        p.error('--length must be between 36 and 1000')
    if args.posterior_samples < 256:
        p.error('--posterior-samples must be >=256')
    root = args.root.expanduser().resolve()
    revision = root/'Revision_31343'
    module_path = revision/'IJAI_31343_Stage7_Instrumented/Pi_Gateway/intelligent_key_renewal.py'
    output = (args.output.expanduser().resolve() if args.output else
              revision/'Experimental_Results/Stage7_Fixed_vs_Adaptive/AI_Adversarial_Statistics')
    if not module_path.is_file():
        p.error(f'Cannot find source model: {module_path}')
    if output == module_path.parent or output.is_relative_to(module_path.parent) or module_path.is_relative_to(output):
        p.error('Output must not overlap module source directory')
    mod = import_module(module_path)
    global _CACHED_SOURCE_MODEL
    _CACHED_SOURCE_MODEL = mod
    tests = run_tests(mod)
    if any(t['result']!='PASS' for t in tests):
        print('NEGATIVE TEST FAILURE:')
        for t in tests: print(t)
        raise SystemExit(2)

    agg_replicates = {}
    raw_replicates = []
    pred_replicates = []
    synthetic_sample_timelines = {}
    for sidx, scenario in enumerate(SCENARIOS):
        for replica in range(args.replicates):
            seed = BASE_SEED + sidx * 100_000 + replica
            labels = simulate_labels(scenario, seed, args.length)
            decisions = evaluate_sequence(mod, labels, args.posterior_samples)
            if replica == 0:
                synthetic_sample_timelines[scenario] = decisions
            pred_replicates.append({
                'scenario':scenario,'replicate':replica,'synthetic_seed':seed,
                'brier_cumulative':st.mean(x['brier_cumulative'] for x in decisions),
                'brier_window20':st.mean(x['brier_window20'] for x in decisions),
                'brier_constant0p05':st.mean(x['brier_constant0p05'] for x in decisions),
            })
            for policy in POLICIES:
                intervals = [x[policy] for x in decisions]
                row = {
                    'scenario': scenario, 'replicate': replica, 'synthetic_seed': seed,
                    'policy': policy, 'n_observations': args.length,
                    'n_suspicious_inputs': sum(x!='success' for x in labels),
                    'mean_interval_s': st.mean(intervals),
                    'min_interval_s': min(intervals),
                    'max_interval_s': max(intervals),
                    'final_interval_s': intervals[-1],
                    'fraction_below_60_s': sum(x < 60 for x in intervals)/len(intervals),
                    'nominal_frequency_pressure_per_hour': st.mean(3600.0/x for x in intervals),
                }
                raw_replicates.append(row)
                agg_replicates.setdefault((scenario,policy), []).append(row)
    random_bootstrap = random.Random(BASE_SEED + 777)
    aggregate = []
    comparisons = []
    for scenario in SCENARIOS:
        for policy in POLICIES:
            rr = agg_replicates[(scenario, policy)]
            ms = [r['mean_interval_s'] for r in rr]
            pressure = [r['nominal_frequency_pressure_per_hour'] for r in rr]
            interval_stats = simple_stats(ms, random_bootstrap)
            pressure_stats = simple_stats(pressure, random_bootstrap)
            aggregate.append({
                'scenario': scenario, 'policy': policy,
                'n_synthetic_replicates': args.replicates,
                'mean_interval_s': interval_stats['mean'],
                'sd_of_replicate_means_s': interval_stats['sd_across_sequences'],
                'bootstrap95_mean_interval_low_s': interval_stats['bootstrap_95_low'],
                'bootstrap95_mean_interval_high_s': interval_stats['bootstrap_95_high'],
                'mean_nominal_frequency_pressure_per_hour': pressure_stats['mean'],
                'bootstrap95_pressure_low': pressure_stats['bootstrap_95_low'],
                'bootstrap95_pressure_high': pressure_stats['bootstrap_95_high'],
                'mean_fraction_below_60_s': st.mean(r['fraction_below_60_s'] for r in rr),
            })
        baseline = agg_replicates[(scenario,'heuristic_2of5')]
        model = agg_replicates[(scenario,'bayes_upper_lambda4')]
        diffs = [m['mean_interval_s']-h['mean_interval_s'] for m,h in zip(model, baseline)]
        s = simple_stats(diffs, random_bootstrap)
        comparisons.append({'scenario':scenario,'comparison':'bayes_lambda4_minus_heuristic2of5',
                            'n_paired_synthetic_seeds':args.replicates,
                            'paired_mean_difference_s':s['mean'],
                            'bootstrap95_difference_low_s':s['bootstrap_95_low'],
                            'bootstrap95_difference_high_s':s['bootstrap_95_high']})

    pred_aggregates=[]
    for scenario in SCENARIOS:
        runs=[r for r in pred_replicates if r['scenario']==scenario]
        for predictor in ('cumulative','window20','constant0p05'):
            col='brier_'+predictor
            s=simple_stats([r[col] for r in runs],random_bootstrap)
            pred_aggregates.append({'scenario':scenario,'predictor':predictor,
                                    'n_independent_synthetic_replicates':args.replicates,
                                    'mean_prequential_brier':s['mean'],
                                    'sd_across_replicates':s['sd_across_sequences'],
                                    'bootstrap95_brier_low':s['bootstrap_95_low'],
                                    'bootstrap95_brier_high':s['bootstrap_95_high']})

    # Monte Carlo quantile approximation stability (largest N is a reference,
    # not an exact 95% posterior quantile).
    mc_stability = []
    for n_ok, n_bad in ((10,0),(10,5),(40,10),(100,0),(20,30)):
        q = {}
        for ndraws in (256,1024,4096,16384):
            q[ndraws] = mk_model(mod,1,19,n_ok,n_bad,ndraws).posterior_upper_bound()
        for ndraws in (256,1024,4096,16384):
            mc_stability.append({'normal_events':n_ok,'suspicious_events':n_bad,
                                 'mc_samples':ndraws,'posterior_upper_mc':q[ndraws],
                                 'abs_diff_vs_16384_draw_reference':abs(q[ndraws]-q[16384])})

    output.mkdir(parents=True, exist_ok=True)
    write_csv(output/'synthetic_replicate_results.csv',raw_replicates,list(raw_replicates[0]))
    write_csv(output/'synthetic_scenario_aggregates.csv',aggregate,list(aggregate[0]))
    write_csv(output/'paired_policy_differences.csv',comparisons,list(comparisons[0]))
    write_csv(output/'posterior_mc_stability.csv',mc_stability,list(mc_stability[0]))
    write_csv(output/'synthetic_prequential_brier_replicates.csv', pred_replicates,list(pred_replicates[0]))
    write_csv(output/'synthetic_prequential_brier_aggregates.csv', pred_aggregates,list(pred_aggregates[0]))
    report = {
        'research_scope':'synthetic input stress tests for an existing Bayesian rotation controller',
        'date_utc':datetime.now(timezone.utc).isoformat(),
        'model_sha256':sha256(module_path),
        'model_path':str(module_path),
        'scenarios':list(SCENARIOS),
        'policies':list(POLICIES),
        'simulation_settings':{'replicates_per_scenario':args.replicates,'observations_per_rep':args.length,
                               'feedback_sensitivity':'every generated observation is one Bayesian update',
                               'seed_base':BASE_SEED,'posterior_samples':args.posterior_samples,
                               'prior_primary':[1,19], 'confidence':.95,
                               'lambda_primary':4, 'assumed_horizon_s':HORIZON,
                               'horizon_is_measured':False},
        'security_unit_tests':tests,
        'synthetic_samples_are_not_hardware_trials':True,
        'important_limitations':[
            'All scenarios are designed synthetic gateway feedback, not captured attacks or labels proving compromise.',
            'Different policies receive the same exogenous observations. In real deployments, observations may depend on policy and rotation schedule.',
            'Nominal frequency pressure = average 3600/T across snapshot intervals. It is NOT measured rotations, power, or network load.',
            'Bootstrap resamples independent seeded synthetic sequences. Its CI quantifies variability of the simulator, NOT hardware or security effectiveness.',
            'Beta-Bernoulli assumes exchangeability; it does not detect unknown attacks, learn adversary capabilities, or predict cryptanalytic time-to-break.',
            'Prior, lambda, alert probabilities and scenario horizon were not optimized on an independent validation dataset.',
            'Window20 policy is only a SIMULATED candidate and not implemented or validated in the Stage7 gateway.',
            'The Monte Carlo 16384-sample posterior quantile is an approximation reference, NOT an exact credible bound.',
            'Prequential Brier scores predict SYNTHETIC suspicious feedback labels, not real attacks; cannot be reported as IDS precision/recall.',
            'False alert floods can force shorter intervals and impose denial-of-service costs; current model does not distinguish authentic vs attacker-induced alerts.',
            'The controller is a key-lifetime selector, not an ECC cryptographic protocol. It cannot by itself establish forward secrecy or post-compromise recovery.',
        ],
    }
    (output/'simulation_manifest.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    real_replay = revision/'Experimental_Results/Stage7_Fixed_vs_Adaptive/AI_Policy_Replay/stage4_policy_decision_replay.csv'
    fig_names = [] if args.no_plots else plotting(output,synthetic_sample_timelines,real_replay)
    (output/'README_SCIENTIFIC_LIMITATIONS.txt').write_text('''IJ-AI 31343 — Offline risk-controller adversarial-input assessment

This program replays synthetic observations through the existing Stage7 Bayesian estimator.
Reproduction requires the Stage7 source model and the recorded seeds and settings in
simulation_manifest.json. No ESP8266, ESP32, Raspberry Pi, or EOSIO device was contacted.

Scenarios (all SYNTHETIC):
- benign: 1% invalid feedback probability each observation.
- burst_invalid_proofs: two deterministic 6-observation invalid-proof bursts;
  otherwise 1% invalid feedback.
- step_rise: middle third has 45% invalid feedback, otherwise 1%.
- gradual_ramp: invalid-feedback probability increases linearly from 1% to 50%.
- attack_then_recovery: index one-sixth to one-half has 65% invalid feedback;
  otherwise 1%. Cumulative Bayesian counts have no forgetting window.
- forged_alarm_flood: middle third contains false alarm events at every step.
  This does not demonstrate an exploit, just a policy response to manipulated input.

Policies: fixed60, fixed90, fixed120; illustrative 2-of-last-5 heuristic;
Bayesian upper quantile lambda=2,4,8; posterior-mean ablation;
OPTIONAL SIMULATION-ONLY candidate: Beta-Bernoulli with rolling 20-observation
window, not integrated into the tested gateway, no security improvement proven;
prior sensitivity (1,9) and (1,49), both with lambda=4.

Nominal frequency pressure proxy: mean over synthetic observations of 3600/T;
it is NOT the count of rotations occurring in one hour, NOT measured
energy/communication or ECC operations. A policy changing the interval may
change observation rates and adversary behavior in an actual network.

Prequential Brier scores score probability before seeing the next synthetic
feedback event; cumulative Beta-Bernoulli is compared against a 20-observation
Beta-Bernoulli window and a constant 5% predictor. They are NOT attack detection
precision or model calibration on field data.

Bootstrap 95% intervals aggregate independent seeded synthetic streams within
one scenario. They do NOT quantify real-world attack efficacy or hardware
uncertainty. Fixed comparisons and feedback have no independent human labels.

Existing Stage4 replay plot, if present, is DESCRIPTIVE, 21 correlated
feedback snapshots from one hardware-assisted run. Not a paired hardware test.

The worst security risk suggested by the 'forged_alarm_flood' simulation is
that uncontrolled adversarial observations can increase renewal pressure.
Proposed engineering mitigations require implementation and test, such as
rate-limiting alerts, authenticating telemetry and safe cooldown/hysteresis.
DO NOT present such mitigations as implemented.

Do not claim: a learned anomaly detector, AES/EOSIO transactions in Stage4
HMAC data, direct electricity savings, reduced compromise probability,
quantum-safe ECC, or formal proof of forward secrecy.
''',encoding='utf-8')

    print('=== IJ-AI 31343 / SYNTHETIC ADVERSARIAL INPUT & STATISTICS ===')
    print(f'Synthetic scenarios: {len(SCENARIOS)} | independent seeded runs/scenario: {args.replicates} | observations/run: {args.length}')
    print(f'Policy configurations: {len(POLICIES)} | negative model checks: {len(tests)} PASS')
    print('Results created in:',output)
    print('\nSCENARIO SUMMARY — Bayesian upper lambda4 (SYNTHETIC):')
    for row in aggregate:
        if row['policy']=='bayes_upper_lambda4':
            print(f"  {row['scenario']:<24} {row['mean_interval_s']:7.2f} s "
                  f"[seed-bootstrap 95%: {row['bootstrap95_mean_interval_low_s']:.2f}–{row['bootstrap95_mean_interval_high_s']:.2f}] "
                  f"pressure proxy {row['mean_nominal_frequency_pressure_per_hour']:.1f}/h")
    print('Synthetic predictive Brier summary (cumulative / window20 / constant):')
    for scenario in SCENARIOS:
        cols=[v['mean_prequential_brier'] for v in pred_aggregates if v['scenario']==scenario]
        print(f'  {scenario:<24} '+ ' / '.join(f'{v:.4f}' for v in cols))
    print('Figures:',', '.join(fig_names) if fig_names else 'none')
    print('Cached posterior states:', posterior_cached.cache_info())
    print('NOTICE: synthetic observations only; no measured energy, attacks prevented or ESP/Pi trials.')

if __name__=='__main__':
    main()
