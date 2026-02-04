# McEliece
A pure Python implementation of the multivariate McEliece cryptosystem  
So slow that I can't even test variants with larger parameters.  
But at least it was successful (in mceliece348864).  
To identify and reject inconsistent variants, I chose to represent all KEM outputs as objects.  
It might not be constant time, but I don't believe an attacker could gain any advantage over Python.  
With python3.10, who included `int.to_bytes` and `int.from_bytes`.
