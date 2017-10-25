## COSE Reverse Engineering in Python

This small project attempts to reverse engineer some COSE functions in Python, to ease porting of COSE to C.

Installation -

Windows -

```
py -3 -m virtualenv ve
ve\scripts\pip install -r requirements.txt
```

Linux -

```
python3 -m virtualenv ve
ve/bin/pip install -r requirements.txt
```


# Technical Notes

"cryptogrpahy" Python package is used. Its elliptic curve components are documented in
https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/.

