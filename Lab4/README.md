# Lab 4 - automated generate yara rule


```
git clone https://github.com/Neo23x0/yarGen.git
python3 ./yarGen/yarGen.py --update
mv ./dbs ./yarGen/
python3 ./yarGen/yarGen.py -m dataset -o test.yara
```