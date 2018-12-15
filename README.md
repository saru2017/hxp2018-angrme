# hxp2018-angrme

https://2018.ctf.link/internal/challenge/de276158-e100-4009-aa3e-31ec113a6c32.html

問題文をよく読みましょう。
「I hope you do not need more than three lines of python to solve this.」を読んでPython 3行で書けるのかー。そら楽勝だ、ぐらいしか考えなかったのが***良くない。***
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
saru@lucifen:~/hxp2018-angrme/angrme$ file angrme
angrme: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, not stripped
```

64bitの実行ファイル。

### checksec

```bash-statement
saru@lucifen:~/hxp2018-angrme/angrme$ checksec --file ./angrme
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   ./angrme
```

canaryはないが、NXとPIEが有効。
バッファオーバフローかな？と一瞬思う。

### strings

ざっと眺めてみるがさすがにflagがそのまま書き込まれている雰囲気は無い。

```bash-statement
saru@lucifen:~/hxp2018-angrme/angrme$ strings angrme | grep GLIB
GLIBC_2.2.5
_exit@@GLIBC_2.2.5
puts@@GLIBC_2.2.5
stdin@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
fgets@@GLIBC_2.2.5
__cxa_finalize@@GLIBC_2.2.5
saru@lucifen:~/hxp2018-angrme/angrme$
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
saru@lucifen:~/hxp2018-angrme/angrme$ ./angrme
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
:(
saru@lucifen:~/hxp2018-angrme/angrme$
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
saru@lucifen:~/hxp2018-angrme/angrme$ objdump -d -M intel angrme |grep 2390 | grep jne | wc -l
37
```

37個。
地道にアセンブラを追っていくしかないのか．．．
「I hope you do not need more than three lines of python to solve this.」
に関しても確かにflagを書いたpythonプログラムを書けば3行で終わるか、ぐらいにしか考えなかった。


### slackに状況を送ってみる

![slack](fig/slack001.png "slack")

なんとangrというツールを使えばできるらしい．．．
ショック。
でも仲間と相談してやるのは重要なんだなと再認識。

## angrを使う

### angrとは



### まとめると

1. 文字列を受け取る
2. おそらく



