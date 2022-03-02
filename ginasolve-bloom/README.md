## bloom filter
We have $n$ objects. Each object $o$ corresponds to hash buckets $h_1(o)$, ...,
$h_k(o)$. "Hash bucket" here means a binary unit vector. Number of buckets is
$m$

Write $h(o) = \sum_i h_i(o)$.

We want to solve for a subset $S$ of the objects such that:
$\sum_{s \in S} h(s) = b$, where $b$ is some constant integer vector.

We set this up as an integer matrix equality problem of the form: $Ax = b$,
where:
- $b$ is as before, a vector of size $m$.
- $x$ is a binary vector of size $n$, with $1$ in slot $i$ iff the $i$th object
  is in $S$.
- $A$ is a matrix of $m$ rows, $n$ columns where $j$th column is the vector
  $h(o)$.

So $A$, $b$ have non-negative integer entries, and we want a $0$--$1$ vector
$x$ that solves $Ax = b$.

Should ideally make use of sparsity of $A$ somehow here.

