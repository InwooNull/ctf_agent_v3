# Pwn image for the container (untrusted) sandbox profile.
# Base is already present locally; do not pull it. apt/pip/git need network at
# BUILD time only (free, public packages); every run is --network none.
#
# Required: gdb, gcc, libc6-dev, binutils, file, python3 + pip pwntools, ROPgadget.
# Optional (best-effort, never fail the build): pwndbg (pip), one_gadget (ruby gem).
# Installed versions are recorded in /opt/ctfagent/pwn_versions.txt.
FROM python:3.12-slim-bookworm

# --- required apt packages -------------------------------------------------
# pkg-config + git help some pwntools deps build; all are build-time only.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gdb gcc libc6-dev binutils file pkg-config git \
    && rm -rf /var/lib/apt/lists/*

# --- required pip packages -------------------------------------------------
# Pinned for reproducibility. pwntools pulls pyelftools/capstone/ropgadget etc.
RUN pip install --no-cache-dir \
        "pwntools==4.14.1" \
        "ROPgadget==7.6"

# --- record required versions ---------------------------------------------
RUN mkdir -p /opt/ctfagent \
    && { echo "# ctfagent-pwn:0.1 installed versions"; \
         dpkg-query -W -f='${Package}=${Version}\n' gdb gcc libc6-dev binutils file pkg-config git; \
         python3 --version; \
         pip show pwntools 2>/dev/null | sed -n 's/^\(Name\|Version\): /pip:&/p' | tr '\n' ' '; echo; \
         pip show ROPgadget 2>/dev/null | sed -n 's/^\(Name\|Version\): /pip:&/p' | tr '\n' ' '; echo; \
       } > /opt/ctfagent/pwn_versions.txt

# --- optional: pwndbg (pip install, not the heavy git setup) ----------------
# Best-effort: a failure must not abort the build; record the outcome.
RUN { pip install --no-cache-dir "pwndbg==2024.08.29" \
        && echo "pwndbg=$(pip show pwndbg 2>/dev/null | sed -n 's/^Version: //p') (pip)" ; } \
      >> /opt/ctfagent/pwn_versions.txt 2>&1 \
    || echo "pwndbg=ABSENT (pip install failed; suggest: pin a working release or use the git setup.sh)" \
         >> /opt/ctfagent/pwn_versions.txt

# --- optional: one_gadget (ruby gem) ----------------------------------------
RUN { apt-get update \
        && apt-get install -y --no-install-recommends ruby \
        && gem install --no-document one_gadget -v 1.9.0 \
        && echo "one_gadget=$(one_gadget --version 2>/dev/null) (gem); ruby=$(ruby -e 'print RUBY_VERSION')" ; } \
      >> /opt/ctfagent/pwn_versions.txt 2>&1 \
    || echo "one_gadget=ABSENT (ruby/gem install failed; suggest: pin ruby + gem one_gadget offline .gem)" \
         >> /opt/ctfagent/pwn_versions.txt
RUN rm -rf /var/lib/apt/lists/*

# --- build-time sanity: required tooling imports/starts ---------------------
ENV TERM=xterm
RUN gcc --version >/dev/null && gdb --version >/dev/null && file --version >/dev/null \
    && objdump --version >/dev/null && ldd --version >/dev/null \
    && python3 -c "from pwn import process, context, ELF, ROP, p64, u64; print('pwntools import ok')" \
    && ROPgadget --version >/dev/null \
    && echo pwn-image-required-ok \
    && cat /opt/ctfagent/pwn_versions.txt

# Non-root by default; the sandbox also forces --user at run time.
USER 65534:65534
