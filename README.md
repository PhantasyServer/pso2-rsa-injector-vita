# PSO2 RSA Injector (Vita)

A (not) "simple" RSA key swapper for the Vita version of PSO2.

Versions for [NGS](https://github.com/AntonnMal/pso2-rsa-injector) and [classic](https://github.com/PhantasyServer/pso2-rsa-injector-classic) are also available.

## Building

> [!NOTE]
> Building on bare Windows is unsupported, use WSL.

You will need to install cmake, gcc, git, [rust compiler](https://www.rust-lang.org/tools/install) and the [Vita SDK](https://vitasdk.org/).

Then run to build:
```
mkdir build
cd build
cmake ..
make
```
Built module will be in `build/pso2_injector.suprx`

## Usage

0) Install [ioPlus](https://github.com/TeamFAPS/PSVita-RE-tools/tree/master/ioPlus/ioPlus-0.1) as a kernel module.
1) Generate a [key pair](https://github.com/cyberkitsune/PSO2Proxy#your-private--public-keypair).
2) (If the server doesn't support auto key negotiation) Copy your `publickey.blob` to `ux0:data/publicKey.blob`.
3) Copy `pso2.toml` to `ux0:data/pso2.toml` and edit it.
4) Copy `pso2_injector.suprx` to `ux0:tai/` (or the `tai` folder on other device if using SD2VITA).
5) Add module to `tai/config.txt`
```
*PCSG00141
ux0:tai/pso2_injector.suprx
```

## Code notes

 - The way rust is integrated is very not good and you shouldn't be using this as some sort of example on how to add rust code to modules.
