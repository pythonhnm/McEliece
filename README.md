# McEliece
A pure Python implementation of the multivariate McEliece cryptosystem  
All variants passed the tests.  
To identify and reject inconsistent variants, I chose to represent all KEM outputs as objects.  
It might not be constant time, but I don't believe an attacker could gain any advantage over Python.  
With python3.10, who included `int.to_bytes` and `int.from_bytes`.  
Performance:  
```
pypy7.3.15(python3.10.13):
mceliece348864:    9.371237993240356
mceliece348864f:   8.367012023925781
mceliece460896:    62.13537049293518
mceliece460896f:	 22.334904432296753
mceliece6688128:	103.77946758270264
mceliece6688128f:	55.42070722579956
mceliece6960119:	94.28469800949097
mceliece6960119f:	48.102853775024414
mceliece8192128:	185.38308882713318
mceliece8192128f:	63.357917070388794
```
