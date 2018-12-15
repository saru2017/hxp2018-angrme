# hxp2018-angrme

hxp CTF 2018で唯一時間内に解けた問題。

https://2018.ctf.link/internal/challenge/de276158-e100-4009-aa3e-31ec113a6c32.html

問題文をよく読みましょう。
「I hope you do not need more than three lines of python to solve this.」を読んでPython 3行で書けるのかー。そら楽勝だ、ぐらいしか考えなかったのが ***良くない。***
何が良くなかったのかは後ほど。

## ざっとしらべる

```bash-statement
$ wget https://2018.ctf.link/assets/files/angrme-9b74a376a923552b.tar.xz
$ xz -d angrme-9b74a376a923552b.tar.xz
$ tar xvf angrme-9b74a376a923552b.tar
angrme/
angrme/angrme
$
```

### file

```bash-statement
$ file angrme
angrme: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, not stripped
```

64bitの実行ファイル。

### checksec

```bash-statement
$ checksec --file ./angrme
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   ./angrme
```

canaryはないが、NXとPIEが有効。
バッファオーバフローかな？と一瞬思う。

### strings

ざっと眺めてみるがさすがにflagがそのまま書き込まれている雰囲気は無い。

```bash-statement
$ strings angrme | grep GLIB
GLIBC_2.2.5
_exit@@GLIBC_2.2.5
puts@@GLIBC_2.2.5
stdin@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
fgets@@GLIBC_2.2.5
__cxa_finalize@@GLIBC_2.2.5
$
```

バッファオーバフローを起こせそうな関数は無い。

### objdump

```bash-statement
$ objdump -d -M intel angrme | less
```

- とにかくmainが長い
- 最初にfgets
- ```jne    2390 <main+0x1230>```がたくさん出てくる


```bash-statement
    2370:       48 8d 3d 90 0c 00 00    lea    rdi,[rip+0xc90]        # 3007 <_IO_st
din_used+0x7>
    2377:       e8 c4 ec ff ff          call   1040 <puts@plt>
    237c:       31 c0                   xor    eax,eax
    237e:       48 81 c4 88 01 00 00    add    rsp,0x188
    2385:       5b                      pop    rbx
    2386:       41 5c                   pop    r12
    2388:       41 5d                   pop    r13
    238a:       41 5e                   pop    r14
    238c:       41 5f                   pop    r15
    238e:       5d                      pop    rbp
    238f:       c3                      ret
    2390:       48 8d 3d 6d 0c 00 00    lea    rdi,[rip+0xc6d]        # 3004 <_IO_stdin_used+0x4>
    2397:       e8 a4 ec ff ff          call   1040 <puts@plt>
    239c:       bf ff ff ff ff          mov    edi,0xffffffff
    23a1:       e8 8a ec ff ff          call   1030 <_exit@plt>
    23a6:       66 2e 0f 1f 84 00 00    nop    WORD PTR cs:[rax+rax*1+0x0]
    23ad:       00 00 00

```

mainの最後あたり。
なんかputsしている。
2390にとんだ後も何かputsしている。


### 実行してみる

```bash-statement
$ ./angrme
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
:(
$
```

たぶん2390に飛んだあと```:(```をputsしていると予測。


### gdbで動作を追う

```bash-statement
$ gdb angrme
gdb-peda$ start
gdb-peda$ ni
```

のあとni (next instruction)を実行しながらチェック。
fgetsで文字列を読み込んだあとは文字列からごちゃごちゃしながら最後
```bash-statement
=> 0x555555555241 <main+225>:   cmp    eax,0x92
   0x555555555246 <main+230>:   jne    0x555555556390 <main+4656>
```
となる。
つまりいろいろ演算した結果がcmp eax,0x92に等しくなかったら例の```jne    2390 <main+0x1230>```で最後に飛んで```:(```が出力される。
ここでおそらく入力がflagに等しかったら```jne    2390 <main+0x1230>```に行かずもう一つのputsが呼ばれるのではないかと予測。

### 入力をhxp{AAAAAAAAA}みたいにして動作を追う

フラグの最初はhxpなはずなのでそれを入力したら最初の```jne    2390 <main+0x1230>```ぐらいは超えてくれるのではないかと予想。

が、1個めではじかれる。

試しに```jne    2390 <main+0x1230>```の数を数えてみる。

```
$ objdump -d -M intel angrme |grep 2390 | grep jne | wc -l
37
```

37個。
地道にアセンブラを追っていくしかないのか．．．
「I hope you do not need more than three lines of python to solve this.」
に関しても確かにflagを書いたpythonプログラムを書けば3行で終わるか、ぐらいにしか考えなかった。

### まとめると

1. 文字列を受け取る
2. おそらく受け取った文字列がフラグなら正解のメッセージが表示される
3. フラグかどうかはいろんな計算をごにょごにょして途中途中の計算結果をチェックしながら違った場合には```jne    2390 <main+0x1230>```で最後に飛ぶ
4. どんな計算をしてるか分かればFLAGも逆算できるはず！


### slackに状況を送ってみる

![slack](fig/slack001.png "slack")

なんとangrというツールを使えばできるらしい．．．
ショック。
でも仲間と相談してやるのは重要なんだなと再認識。

## angrを使う

### angrとは

https://angr.io/ で公開されているバイナリ分析ツール。

行ったらいけないアドレス、行ったら成功のアドレスを教えるだけで入力を全探索してくれるみたい。

いつもお世話になっている「ももいろテクノロジー」さんのところにも載っていた。
[angrでシンボリック実行をやってみる - ももいろテクノロジー](http://inaz2.hatenablog.com/entry/2016/03/16/190756)

> シンボリック実行とは、プログラム上の変数をシンボルとして扱い、シンボルに対する一連の操作を分析することで条件を満たす入力値を特定するプログラム解析手法である。 ここでは、CTFチームShellphishが開発しているバイナリ解析ツールangrを使い、簡単なプログラムに対してシンボリック実行を適用してみる。

こいつはすごい。

### angrのインストール

pipで入るのだけど実行ができない．．．

condaを使ってpython 3.7を使える環境を作る。

```bash-statement
$ conda create -n angr3.7 python=3.7
$ conda info -e
# conda environments:
#
angr3.4                  /home/saru/.pyenv/versions/anaconda3-4.4.0/envs/angr3.4
angr3.7                  /home/saru/.pyenv/versions/anaconda3-4.4.0/envs/angr3.7
root                  *  /home/saru/.pyenv/versions/anaconda3-4.4.0

$
```

angr3.7に切り替える

```
$ source activate angr3.7
(angr3.7) $
```

実行できた環境は以下の通り。

```
(angr3.7) $ pip list
Package          Version
---------------- -------------
ailment          8.18.10.25
ana              0.5
angr             8.18.10.25
archinfo         8.18.10.25
bitstring        3.1.5
cachetools       3.0.0
capstone         3.0.5.post1
certifi          2018.10.15
cffi             1.11.5
claripy          8.18.10.25
cle              8.18.10.25
cooldict         1.4
decorator        4.3.0
dpkt             1.9.1
future           0.17.1
gitdb2           2.0.5
GitPython        2.1.11
idalink          0.12
mulpyplexer      0.8
networkx         2.2
pefile           2018.8.8
pip              18.1
plumbum          1.6.7
progressbar      2.5
pycparser        2.19
pyelftools       0.25
pyvex            8.18.10.25
rpyc             4.0.2
setuptools       40.6.2
smmap2           2.0.5
sortedcontainers 2.1.0
unicorn          1.0.1
wheel            0.32.3
z3-solver        4.5.1.0.post2
```

### angrでフラグを解く

angrはバージョンによって使い方が全然異なるようなのだけど、必要なのは2つ

1. 成功した場合に実行されるアドレス
2. 失敗した場合に実行されるアドレス

objdumpで調べた通り、成功した場合には

```bash-statement
    236e:       75 20                   jne    2390 <main+0x1230>
    2370:       48 8d 3d 90 0c 00 00    lea    rdi,[rip+0xc90]        # 3007 <_IO_st
din_used+0x7>
    2377:       e8 c4 ec ff ff          call   1040 <puts@plt>
```

なので```0x2377 - main (0x1160) = 4631```でmain + 4631。


失敗した場合には何度もでてきているようにmain + 0x1230　= main + 4656。

mainのアドレスはPIE (Position Independend Executable)が有効なので実行まで分からない。
が、angrで```p.loader.main_object.get_symbol('main').rebased_addr```とすればmainのアドレスも分かる。

というわけでangrを使ったコードは以下の通りとなる。

```python
import angr

p = angr.Project('./angrme')
main_addr = p.loader.main_object.get_symbol('main').rebased_addr
addr_success = main_addr + 4631
addr_fail = main_addr + 4656
sim = p.factory.simgr()
sim.explore(find=addr_success, avoid=addr_fail)
s = sim.found[0]
print(s.posix.dumps(0))
```

実行結果

```bash-statement
(angr3.7) $ python solve.py
WARNING | 2018-12-15 14:51:03,857 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.
WARNING | 2018-12-15 14:51:05,130 | angr.state_plugins.symbolic_memory | Register r15 has an unspecified value; Generating an unconstrained value of 8 bytes.
WARNING | 2018-12-15 14:51:05,132 | angr.state_plugins.symbolic_memory | Register r14 has an unspecified value; Generating an unconstrained value of 8 bytes.
WARNING | 2018-12-15 14:51:05,134 | angr.state_plugins.symbolic_memory | Register r13 has an unspecified value; Generating an unconstrained value of 8 bytes.
WARNING | 2018-12-15 14:51:05,136 | angr.state_plugins.symbolic_memory | Register r12 has an unspecified value; Generating an unconstrained value of 8 bytes.
WARNING | 2018-12-15 14:51:05,140 | angr.state_plugins.symbolic_memory | Register rbx has an unspecified value; Generating an unconstrained value of 8 bytes.
WARNING | 2018-12-15 14:51:05,182 | angr.state_plugins.symbolic_memory | Register cc_ndep has an unspecified value; Generating an unconstrained value of 8 bytes.
b'hxp{xxxxxxxxxxxxxxxx}'
(angr3.7) $
```

最後にcondaのangr3.7環境を抜ける。

```bash-statement
(angr3.7) $ source deactivate
$
```

面白かった。
