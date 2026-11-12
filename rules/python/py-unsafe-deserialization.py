import json
import pickle

import torch
import yaml


def load_session(blob):
    # ruleid: py-unsafe-deserialization
    return pickle.loads(blob)


def load_config(path):
    with open(path) as f:
        # ruleid: py-unsafe-deserialization
        return yaml.load(f)


def load_config_full(text):
    # ruleid: py-unsafe-deserialization
    return yaml.load(text, Loader=yaml.FullLoader)


def load_model(path):
    # ruleid: py-unsafe-deserialization
    return torch.load(path, weights_only=False)


def load_rng_state(rng_file):
    # ruleid: py-unsafe-deserialization
    return torch.load(rng_file)


def safe_config(text):
    # ok: py-unsafe-deserialization
    return yaml.safe_load(text)


def safe_config_loader(text):
    # ok: py-unsafe-deserialization
    return yaml.load(text, Loader=yaml.SafeLoader)


def safe_model(path):
    # ok: py-unsafe-deserialization
    return torch.load(path, weights_only=True)


def safe_json(blob):
    # ok: py-unsafe-deserialization
    return json.loads(blob)
