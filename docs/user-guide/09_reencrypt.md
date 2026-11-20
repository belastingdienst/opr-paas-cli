---
title: Reencryption
summary: A description of the reencrypt subcommand
authors:
  - Devotional Phoenix
date: 2026-05-21
---

# Re-encrypting secrets with a new key

The most common use case is to re-encrypt secrets in PAAS files using a new key:

`kubectl-paas reencrypt --privateKeyFiles "/tmp/priv" --publicKeyFile "/tmp/pub" [file or dir] ([file or dir]...)`

!!! note
    Re-encryption without `--outputFormat preserve` will always convert to the latest api version (currently v1alpha2).
    `--outputFormat preserve` has no extra validation on version and works for all currently known versions.
    This may change in the future.
    Because `--outputFormat preserve` replaces each encrypted value in the file itself, it cannot replace a value
    that spans several lines. Re-encryption then fails without writing any file; use `--outputFormat auto` instead.

## Label and annotation filters

We have implemented a feature to filter Paas'es depending on labels and annotations.
The main implementation resembles the -l option of kubectl as closely as possible, but:
- We have more options with ! and =
- We have also implemented this for Annotations

Main goal is to be able to skip Paas'es with argocd annotations.
An overview of how it works:
- You can specify one or more label filters with the -l, or --selector arguments, or with the `PAAS_LABEL_SELECTOR` environment variable.
- You can also specify one or more label filters with the -a, or --annotations arguments, or with the `PAAS_ANNOTATION_SELECTOR` environment variable.
- If you want to specify more then one filter, add them as a comma seperated list
- You have the following options to specify a filter:
  - If you want to include a paas if the key is set, only specify the key (e.a. `includedKey`).
  - If you want to exclude a paas if the key is set, specify the key, and negate the filter by adding a exclamation sign (e.a. `excludedKey!`).
  - If you want to include a paas if the key is set to a specific value, specify this in the form of `key=value`
  - If you want to exclude a paas if the key is set to a specific value, specify this in the form of `key!=value`
    (note that both `!=` and `=!` work, but for readability the former is adviced over the latter)

!!! example

    ```bash
    # reencrypt all Paas'es with a label infra=... set
    kubectl paas reencrypt -l 'infra'

    # reencrypt all Paas'es with a label `infra` set to `paas`
    kubectl paas reencrypt -l 'infra=paas'

    # reencrypt all Paas'es except those with a label `appteam` set
    kubectl paas reencrypt -l 'appteam!'

    # reencrypt only Paas'es with a label `appteam` except those with a label `appteam` set to `appteam1`
    kubectl paas reencrypt -l 'appteam,appteam!=appteam1'

    # filter out those that are argocd managed:
    kubectl paas reencrypt -a 'argocd.argoproj.io/instance!'
    ```
