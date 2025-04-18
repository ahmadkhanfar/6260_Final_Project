Parallel UAV Authentication using DRIP, Ed25519, and OpenMP
This project implements a high-performance authentication system for Unmanned Aerial Vehicles (UAVs) based on the Drone Remote Identification Protocol (DRIP). It uses Ed25519 digital signatures for cryptographic verification and accelerates the process using OpenMP for multithreaded execution.

 Key Features
 DRIP-compliant message structure (DET, public key, signature, wrapper)

Ed25519 signature verification via Libsodium

Sequential vs. parallel performance comparison

Benchmarking for valid and invalid messages

 Built-in test set: 1000 valid + 500 invalid UAV messages

Technologies
C++

OpenMP (parallel processing)

Libsodium (crypto)

g++ (compiler)

Ubuntu/Linux

How to Run
Install Libsodium:
sudo apt install libsodium-dev

Compile:
g++ -fopenmp -lsodium -o uav_auth main.cpp

Run:
./uav_auth

Output
Per-message verification timing

Total verification throughput

Speedup gained from multithreading

