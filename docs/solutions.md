# Signer's Solutions

- TODO 1.2: Call the appropriate nonce generation FROST API on the above inputs
```python
secnonce, pubnonce = frost.nonce_gen(
    secshare=secshare,
    pubshare=pubshare,
    group_pk=group_pk_xonly,
    msg=MESSAGE_BYTES,
    extra_in=None,
)
```
- TODO 2.2: Create a signature using FROST API on the above inputs
```python
psig = frost.sign(
    secnonce=secnonce,
    secshare=secshare,
    my_id=MY_IDENTIFIER,
    session_ctx=session_ctx,
)
```

# Aggregator's Solutions

- TODO 1.3: Call the appropriate nonce aggregation FROST API on the above inputs
```python
aggnonce = frost.nonce_agg(pubnonces=pubnonces, ids=PARTICIPANT_IDS)
```

- TODO 2.2: Aggregate the partial signatures using the appropriate FROST API
```python
aggregated_sig = frost.partial_sig_agg(partial_sigs, PARTICIPANT_IDS, session_ctx)
```