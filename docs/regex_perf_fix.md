# Regex fix: `getMainFunc()`

## Before

```python
re.findall(r".+?\(0\);.+?\(1\);.+?\(2\);", ccode)
```

Three chained lazy quantifiers, no anchor. Backtracks quadratically on large decompiled functions. 99KB function: 426s, zero matches.

## After

```python
def countCloseSeq(text):
    total = 0
    for line in text.split("\n"):
        pos = 0
        while True:
            a = line.find("(0);", pos + 1)
            if a < 0: break
            b = line.find("(1);", a + 5)
            if b < 0: break
            c = line.find("(2);", b + 5)
            if c < 0: break
            total += 1
            pos = c + 4
    return total
```

`str.find`, linear. Equivalence with the regex fuzzed over 120,000 random strings, zero mismatches.

## Single sample

`cc40e161d86d…`, 194KB static x86: 455s → 41.8s.

## 226-sample corpus, same code otherwise

| metric | before | after |
|---|--:|--:|
| timeout rate | 19.9% (45/226) | 13.7% (31/226) |
| table extraction | 45.1% | 46.0% |
| C2 extraction | 46.0% | 46.9% |
| domain extraction | 1.8% | 2.2% |
| C2 precision (VT) | 42.4% | 44.1% |
