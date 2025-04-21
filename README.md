# house-of-husk
PoCs for House of Husk in heap exploitation, leveraging Largebin Attacks for demonstration against the most modern versions of glibc.

Details of the house are introduced in this blog post:

To build all, enter the [PoCs directory](https://github.com/4xura/house-of-husk/tree/main/PoCs) and run:

```sh
make
```

To build a specific one (e.g., for glibc 2.35 chain 1):

```sh
make house_of_husk_1_glibc-2.35
```

To clean up all compiled binaries:

```sh
make clean
```

 
