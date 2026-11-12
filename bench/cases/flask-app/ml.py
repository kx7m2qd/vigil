import torch


def load_untrusted(path):
    # expect: py-unsafe-deserialization
    return torch.load(path, weights_only=False)


def load_default(path):
    # Safe only on torch >= 2.6, where weights_only defaults to True; the installed version is
    # unknown at scan time, and this exact shape was CVE-2026-1839 (transformers Trainer).
    # expect: py-unsafe-deserialization
    return torch.load(path)


def load_weights(path):
    return torch.load(path, weights_only=True)
