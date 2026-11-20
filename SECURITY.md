# Security Policy & Responsible Use

## Lab Safety Notice
This repository is an educational **Detection-as-Code & Blue Team / Purple Team Lab**.

- The attack simulator (`simulator/attack_simulator.py`) **never performs real network exploitation or host modification**. It only generates synthetic log files locally for testing detection logic.
- All public IP addresses used in simulated attacks and the local Threat Intelligence feed belong exclusively to **RFC 5737 documentation/test ranges** (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and **RFC 1918 private ranges** (`10.0.0.0/8`, `192.168.0.0/16`).

## Reporting a Vulnerability
If you identify a security issue in the detection engine, CI workflows, or webhook handling, please open a private security advisory or report it directly to the maintainer (`PH-Vidal`).
