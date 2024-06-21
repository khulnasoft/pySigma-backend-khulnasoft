![Tests](https://github.com/khulnasoft/pySigma-backend-khulnasoft/actions/workflows/test.yml/badge.svg)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma Khulnasoft Backend

This is the Khulnasoft backend for pySigma. It provides the package `sigma.backends.khulnasoft` with the `KhulnasoftBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.khulnasoft`:

* khulnasoft_windows_pipeline: Khulnasoft Windows log support
* khulnasoft_windows_sysmon_acceleration_keywords: Adds fiels name keyword search terms to generated query to accelerate search.

It supports the following output formats:

* default: plain Khulnasoft queries
* savedsearches: Khulnasoft savedsearches.conf format.
