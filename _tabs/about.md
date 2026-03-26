---
# the default layout is 'page'
icon: fas fa-info-circle
order: 4
---

## Abhinav Agarwal

Sr. Software Developer at [Rubrik](https://www.rubrik.com), working on high-throughput distributed filesystems in cloud environments. Previously optimized latency at high-frequency trading firms. MS in Computer Science from UW–Madison, B.Tech from IIT Kharagpur.

I build storage systems in C/C++ and spend my time thinking about Linux kernel internals, memory safety, io_uring, and FUSE. When I'm not writing filesystem code, I'm usually breaking it.

### Security Advisories

| CVE | Severity | What | Status |
|-----|----------|------|--------|
| [CVE-2026-33150](https://nvd.nist.gov/vuln/detail/CVE-2026-33150) | CVSS 7.8 HIGH | Use-After-Free in libfuse io_uring | Fixed in 3.18.2 |
| [CVE-2026-33179](https://nvd.nist.gov/vuln/detail/CVE-2026-33179) | CVSS 5.5 MEDIUM | NULL deref + memory leak in libfuse io_uring | Fixed in 3.18.2 |
| OpenSSL (TBD) | TBD | Coming soon | Under coordinated disclosure |

Writeup: [RingWraith — libfuse io_uring vulnerabilities](/posts/ringwraith/)

### Talks

- **"Highly Scalable, Masterless, Distributed Filesystem at Rubrik"** — [SNIA Storage Developer Conference 2025](https://www.snia.org/sniadeveloper/session/19384)
- **"SymEngine: A Fast Symbolic Manipulation Library"** — [SciPy 2016](https://scipy2016.scipy.org/)

### Writing

- [Super Fast Circular Ring Buffer Using Virtual Memory Trick](https://abhinavag.medium.com/a-fast-circular-ring-buffer-4d102ef4d4a3)
- [Speculative Execution, SPECTRE and Why You Should Care](https://abhinavag.medium.com/speculative-execution-and-why-you-should-care-8a930c612ddd)

### Contact

- GitHub: [@abhinavagarwal07](https://github.com/abhinavagarwal07)
- Twitter/X: [@abhinav_sec](https://twitter.com/abhinav_sec)
- LinkedIn: [abhinav007](https://www.linkedin.com/in/abhinav007/)
- Email: abhinav [dot] agarwal [at] rubrik [dot] com
