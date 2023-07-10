# RSAES Cryptosystem

## Integrantes da dupla

- Bruno Fernandes Teixeira - 190097540
- Luiz Carlos Schonarth Junior - 190055171

## Pre-requisitos

- Biblioteca GMP (Gnu Multiprecision Library)
- Biblioteca OpenSSL (para uso do SHA256)
- `make`

## Compilando o codigo

Compilando a versao com prints de debug

```
$ make
```

## Rodando o programa

```
$ ./build/use_case
```

## Versao de release

Lembre-se de limpar os arquivos objetos antes de compilar uma versao diferente:

```
$ make clean
$ make release  # Agora a versao de release foi compilada corretamente
$ ./build/use_case
```
