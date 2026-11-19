"""Machine Learning Intelligence: specialised analytical services, not one model.

* EntityResolutionModel  - logistic regression over pairwise identifier-evidence features.
* AnomalyModel           - IsolationForest over per-observation change vectors.

HONESTY NOTE: with no labelled history on first start, both models are bootstrapped from
SYNTHETIC data generated here (data_origin='synthetic-bootstrap' in model_runs). Their output is
therefore a *prediction* that must be labelled as such. The anomaly model retrains on the
platform's own change vectors once enough exist; analyst reviews (true/false positive) are
stored so real evaluation is possible. Nothing here is a calibrated probability of compromise.
"""
import logging
import math
import random
import re
import threading

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_score, recall_score, roc_auc_score

from ..config import settings
from ..db import session_scope
from ..models import EvalVector, ModelRun
from ..util import now

log = logging.getLogger("asivm.ml")
_lock = threading.Lock()


# ----------------------------------------------------------------------------- entity resolution
class EntityResolutionModel:
    name = "entity-resolution"

    def __init__(self):
        self.clf = None
        self.version = "deepsight-identity-1.1.0-untrained"
        self.metrics = {}
        self.errors = 0
        self.inferences = 0

    def train(self, n_assets=400, seed=7):
        from .identity import FEATURES, pair_features, vec
        rng = random.Random(seed)
        fleet = [_sim_asset(rng, i) for i in range(n_assets)]
        X, y = [], []
        for _ in range(7000):
            a = rng.choice(fleet)
            if rng.random() < 0.5:
                obs_ids, obs_os = _sim_observation(rng, a)
                label, cand = 1, a
            else:
                cand = rng.choice(fleet)
                if cand is a:
                    continue
                label = 0
                mode = rng.random()
                obs_ids, obs_os = _sim_observation(rng, a)
                if mode < 0.30 and a["ips"]:           # IP reuse (DHCP) by a different device
                    obs_ids = {**obs_ids, "ip": [cand["ip"]]}
                elif mode < 0.55 and a["host"]:        # sibling hostname differing by digits
                    h = a["host"]
                    sib = re.sub(r"(\d+)", lambda m: str(int(m.group(1)) + 1).zfill(len(m.group(1))), h, count=1)
                    cand = {**cand, "host": sib, "hosts": {sib}}
                    obs_ids = {**obs_ids, "hostname": [h]}
                elif mode < 0.70:                      # same subnet + same OS, otherwise unrelated
                    pass
            f, hard, _ = pair_features(obs_ids, obs_os, _cand_map(cand), cand["os"])
            if hard:
                continue
            X.append(vec(f))
            y.append(label)
        X, y = np.array(X), np.array(y)
        idx = np.arange(len(y))
        rng2 = np.random.RandomState(seed)
        rng2.shuffle(idx)
        cut = int(len(idx) * 0.8)
        tr, te = idx[:cut], idx[cut:]
        clf = LogisticRegression(max_iter=2000, C=2.0)
        clf.fit(X[tr], y[tr])
        p = clf.predict_proba(X[te])[:, 1]
        pred = (p >= 0.5).astype(int)
        hi = p >= 0.85
        self.metrics = {
            "holdout_n": int(len(te)), "auc": round(float(roc_auc_score(y[te], p)), 4),
            "precision@0.5": round(float(precision_score(y[te], pred, zero_division=0)), 4),
            "recall@0.5": round(float(recall_score(y[te], pred, zero_division=0)), 4),
            "false_merge_rate@0.85": round(float(((y[te] == 0) & hi).sum() / max(1, hi.sum())), 4),
            "train_n": int(len(tr)),
            "caveat": "Evaluated on synthetic pairs from the same generator; real-world performance is unknown "
                      "until analyst-validated identity decisions accumulate.",
        }
        self.clf = clf
        self.version = f"deepsight-identity-1.1.0-seed{seed}"
        return self.metrics

    def proba(self, x):
        if self.clf is None:
            self.train()
        try:
            self.inferences += 1
            return float(self.clf.predict_proba([x])[0][1])
        except Exception:
            self.errors += 1
            log.exception("entity model inference failed")
            return 0.0




def _rand_mac(rng):
    return ":".join(f"{rng.randrange(256):02x}" for _ in range(6))


def _sim_asset(rng, i):
    role = rng.choice(["web", "app", "db", "cache", "ws", "fs", "api", "build", "mail", "vpn"])
    num = rng.randrange(1, 30)
    host = f"{role}-{'server' if role in ('app','db','web','fs','mail') else 'node'}-{num:02d}"
    dom = rng.choice(["", ".corp.local", ".prod.example.com", ".internal"])
    subnet = rng.randrange(1, 40)
    ip = f"10.{rng.randrange(0, 4)}.{subnet}.{rng.randrange(2, 250)}"
    a = {
        "host": host + dom, "hosts": {host + dom}, "ip": ip, "ips": {ip},
        "macs": {_rand_mac(rng) for _ in range(rng.choice([1, 1, 1, 2]))},
        "cloud": f"i-{rng.getrandbits(48):012x}" if rng.random() < 0.5 else None,
        "device": f"uuid-{rng.getrandbits(64):016x}" if rng.random() < 0.3 else None,
        "serial": f"sn{rng.getrandbits(40):010x}" if rng.random() < 0.2 else None,
        "os": rng.choice(["linux", "linux", "windows", "network", "macos"]),
    }
    a["hist_ips"] = {f"10.{rng.randrange(0, 4)}.{subnet}.{rng.randrange(2, 250)}"} if rng.random() < 0.3 else set()
    return a


def _cand_map(a):
    m = {"ip": {"all": set(a["ips"]) | set(a["hist_ips"]), "active": set(a["ips"])},
         "mac": {"all": set(a["macs"]), "active": set(a["macs"])}}
    if a["hosts"]:
        m["hostname"] = {"all": set(a["hosts"]), "active": set(a["hosts"])}
    if a["cloud"]:
        m["cloud_id"] = {"all": {a["cloud"]}, "active": {a["cloud"]}}
    if a["device"]:
        m["device_id"] = {"all": {a["device"]}, "active": {a["device"]}}
    if a["serial"]:
        m["serial"] = {"all": {a["serial"]}, "active": {a["serial"]}}
    return m


def _sim_observation(rng, a):
    ids = {}
    present = []
    if rng.random() < 0.8:
        present.append("ip")
    if rng.random() < 0.7:
        present.append("hostname")
    if rng.random() < 0.55:
        present.append("mac")
    if a["cloud"] and rng.random() < 0.6:
        present.append("cloud_id")
    if a["device"] and rng.random() < 0.5:
        present.append("device_id")
    if a["serial"] and rng.random() < 0.4:
        present.append("serial")
    if not present:
        present = ["ip"]
    for k in present:
        if k == "ip":
            if rng.random() < 0.2:  # drifted IP (DHCP change within subnet)
                parts = a["ip"].split(".")
                parts[-1] = str(rng.randrange(2, 250))
                ids["ip"] = [".".join(parts)]
            else:
                ids["ip"] = [a["ip"]]
        elif k == "hostname":
            h = next(iter(a["hosts"]))
            r = rng.random()
            if r < 0.3:
                h = h.split(".")[0]
            elif r < 0.45:
                h = h.split(".")[0] + ".other.example"
            ids["hostname"] = [h]
        elif k == "mac":
            ids["mac"] = [rng.choice(sorted(a["macs"]))]
        elif k == "cloud_id":
            ids["cloud_id"] = [a["cloud"]]
        elif k == "device_id":
            ids["device_id"] = [a["device"]]
        elif k == "serial":
            ids["serial"] = [a["serial"]]
    return ids, (a["os"] if rng.random() < 0.7 else None)


# ----------------------------------------------------------------------------- anomaly detection
ANOM_FEATURES = ["n_new_services", "n_external_new", "max_port_rarity", "admin_port", "db_port", "n_ident_changes",
                 "n_config_changes", "n_version_changes", "criticality", "changes_7d", "days_since_last_change",
                 "off_hours", "service_count"]
ANOM_TEXT = {
    "n_new_services": "number of newly appearing services",
    "n_external_new": "newly exposed externally reachable services",
    "max_port_rarity": "service on a port rarely seen across the fleet",
    "admin_port": "new remote-administration/management port",
    "db_port": "new database/cache port",
    "n_ident_changes": "identifier changes (e.g. IP)",
    "n_config_changes": "configuration changes",
    "n_version_changes": "service version changes",
    "criticality": "asset criticality",
    "changes_7d": "unusually frequent recent changes",
    "days_since_last_change": "change after a long quiet period",
    "off_hours": "change outside normal hours (UTC)",
    "service_count": "number of services on the asset",
}


def _bootstrap_baseline(n=2500, seed=11):
    rng = np.random.RandomState(seed)
    rows = []
    for _ in range(n):
        ns = rng.choice([0, 1, 2], p=[0.55, 0.38, 0.07])
        ext = 1 if (ns and rng.rand() < 0.25) else 0
        rar = rng.beta(1.2, 9) if ns else 0.0
        adm = 1 if (ns and rng.rand() < 0.04) else 0
        dbp = 1 if (ns and rng.rand() < 0.06) else 0
        idc = 1 if rng.rand() < 0.10 else 0
        cfg = rng.choice([0, 1, 2], p=[0.8, 0.17, 0.03])
        ver = rng.choice([0, 1], p=[0.85, 0.15])
        rows.append([ns, ext, rar, adm, dbp, idc, cfg, ver, rng.choice([1, 2, 3, 4, 5]) / 5.0,
                     min(20, rng.poisson(1.5)), min(60, rng.exponential(10)) / 60.0, float(rng.rand() < 0.15),
                     min(40, rng.poisson(6))])
    return np.array(rows, dtype=float)


class AnomalyModel:
    name = "anomaly-detection"

    def __init__(self):
        self.iso = None
        self.version = "deepsight-anomaly-1.1.0-untrained"
        self.threshold = 0.62
        self.mean = None
        self.std = None
        self.metrics = {}
        self.data_origin = "synthetic-bootstrap"
        self.errors = 0
        self.inferences = 0

    def train(self, extra=None, seed=11):
        X = _bootstrap_baseline(seed=seed)
        real_n = 0
        if extra is not None and len(extra) >= 15:
            real_n = len(extra)
            # platform-observed change vectors are weighted x5 so the model learns THIS environment's normal churn
            X = np.vstack([X[:600], np.repeat(np.array(extra, dtype=float), 5, axis=0)])
            self.data_origin = "platform-data+bootstrap"
        else:
            self.data_origin = "synthetic-bootstrap"
        self.iso = IsolationForest(n_estimators=200, contamination="auto", random_state=seed).fit(X)
        scores = -self.iso.score_samples(X)
        self.threshold = float(np.quantile(scores, 0.985))
        self.mean, self.std = X.mean(axis=0), X.std(axis=0) + 1e-6
        self.version = f"deepsight-anomaly-1.1.0-{seed}-{'r' if real_n else 'b'}{real_n or len(X)}"
        self.metrics = {"train_n": int(len(X)), "real_vectors": int(real_n),
                        "threshold_q98.5": round(self.threshold, 4),
                        "caveat": "Unsupervised; flags deviation from historical change patterns, not malice."}
        return self.metrics

    @property
    def effective_threshold(self):
        return settings.anomaly_threshold or self.threshold

    def score(self, feats: dict):
        if self.iso is None:
            self.train()
        x = np.array([[feats[k] for k in ANOM_FEATURES]], dtype=float)
        try:
            self.inferences += 1
            s = float(-self.iso.score_samples(x)[0])
        except Exception:
            self.errors += 1
            log.exception("anomaly inference failed")
            return 0.0, []
        z = ((x[0] - self.mean) / self.std)
        order = np.argsort(-z)[:3]
        contrib = [{"feature": ANOM_FEATURES[i], "label": ANOM_TEXT[ANOM_FEATURES[i]],
                    "value": round(float(x[0][i]), 3), "z": round(float(z[i]), 2)}
                   for i in order if z[i] > 1.0 and x[0][i] > 0]
        return s, contrib


_er = EntityResolutionModel()
_an = AnomalyModel()


def entity_model():
    if _er.clf is None:
        with _lock:
            if _er.clf is None:
                _er.train()
    return _er


def anomaly_model():
    if _an.iso is None:
        with _lock:
            if _an.iso is None:
                _an.train()
    return _an


def register_models():
    """Train bootstrap models and record them in model_runs (model management)."""
    em, am = entity_model(), anomaly_model()
    with session_scope() as db:
        for m, origin in ((em, "synthetic-bootstrap"), (am, am.data_origin)):
            exists = db.query(ModelRun).filter(ModelRun.name == m.name, ModelRun.version == m.version).first()
            if not exists:
                for old in db.query(ModelRun).filter(ModelRun.name == m.name, ModelRun.status == "active"):
                    old.status = "retired"
                db.add(ModelRun(name=m.name, version=m.version, metrics=m.metrics, data_origin=origin,
                                notes=m.metrics.get("caveat")))


def retrain_anomaly():
    with session_scope() as db:
        rows = db.query(EvalVector.features).order_by(EvalVector.id.desc()).limit(20000).all()
        extra = [[r[0][k] for k in ANOM_FEATURES] for r in rows if r[0] and all(k in r[0] for k in ANOM_FEATURES)]
    with _lock:
        _an.train(extra=extra)
    with session_scope() as db:
        for old in db.query(ModelRun).filter(ModelRun.name == _an.name, ModelRun.status == "active"):
            old.status = "retired"
        db.add(ModelRun(name=_an.name, version=_an.version, metrics=_an.metrics, data_origin=_an.data_origin,
                        notes=_an.metrics.get("caveat")))
    return _an.metrics


def model_status(db):
    out = []
    for m in (_er, _an):
        run = db.query(ModelRun).filter(ModelRun.name == m.name, ModelRun.status == "active").first()
        out.append({"name": m.name, "version": m.version, "data_origin": getattr(m, "data_origin", "synthetic-bootstrap"),
                    "trained_at": run.trained_at.isoformat() + "Z" if run else None, "metrics": m.metrics,
                    "inferences": m.inferences, "errors": m.errors,
                    "threshold": round(m.effective_threshold, 4) if hasattr(m, "effective_threshold") else None})
    out.append({"name": "contextual-risk", "version": "deepsight-contextual-risk-1.1.0-heuristic", "data_origin": "none (rule-weighted)",
                "metrics": {"caveat": "Transparent weighted logistic score; UNCALIBRATED. Not a probability of "
                                      "compromise. Needs analyst-validated outcomes before it can be learned."},
                "inferences": None, "errors": 0, "trained_at": None, "threshold": None})
    return out
