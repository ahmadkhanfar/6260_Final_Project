#include <iostream>
#include <vector>
#include <string>
#include <omp.h>
#include <sodium.h>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <cctype>

using namespace std;
using namespace std::chrono;

// Configuration
const string DET_HEX = "2001003FFE040105e4c6ae84e5970447";
const string PUBKEY_HEX = "8929f7b90f585512a3a4c884eb6dce08c0280a3f0654ad4f4ccac646c00400ad";
const string WRAPPER_HEX = "4525f2675533f267445249502f312e30001666fed3ab0263f191c36bb24508ef913c551130488edd1d2e774b3d52524ca32001003ffe040105e4c6ae84e59704476cc7a5455eb663aeb367c102c2136e300e74a47ab3cc500539d6a5b3cb13761f092403326a98046ee8a79aa33f5d4f87219e7437902334b89230345057f53007";

// Case-insensitive hex comparison
bool compare_hex(const string& hex1, const string& hex2) {
    if(hex1.length() != hex2.length()) return false;
    for(size_t i = 0; i < hex1.length(); i++) {
        if(tolower(hex1[i]) != tolower(hex2[i])) return false;
    }
    return true;
}

vector<unsigned char> hex_to_bytes(const string& hex) {
    vector<unsigned char> bytes;
    for(size_t i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(stoul(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

struct VerificationResult {
    bool valid;
    string det;
    double verification_time;
};

VerificationResult verify_wrapper(const vector<unsigned char>& wrapper, 
                                const unsigned char* pubkey) {
    VerificationResult result;
    auto start = high_resolution_clock::now();
    
    if(wrapper.size() < 89) {  // Minimum: VNB(4)+VNA(4)+DET(16)+sig(64)=88
        result.valid = false;
        return result;
    }

    // Extract signature (last 64 bytes)
    vector<unsigned char> sig(wrapper.end()-64, wrapper.end());
    
    // Data to verify is everything before signature (message + DET)
    vector<unsigned char> data_to_verify(wrapper.begin(), wrapper.end()-64);
    
    // Extract DET (last 16 bytes of data_to_verify)
    vector<unsigned char> det_bytes(data_to_verify.end()-16, data_to_verify.end());
    
    // Convert DET to hex
    stringstream det_ss;
    for(auto b : det_bytes) {
        det_ss << hex << setw(2) << setfill('0') << static_cast<int>(b);
    }
    result.det = det_ss.str();

    // Verify signature on data_to_verify (message + DET)
    result.valid = (crypto_sign_verify_detached(
        sig.data(), 
        data_to_verify.data(), 
        data_to_verify.size(), 
        pubkey
    ) == 0);

    auto end = high_resolution_clock::now();
    result.verification_time = duration_cast<microseconds>(end - start).count() / 1000.0;
    
    return result;
}

int main() {
    if(sodium_init() == -1) {
        cerr << "Libsodium initialization failed" << endl;
        return 1;
    }

    // Convert keys and wrapper
    auto pubkey = hex_to_bytes(PUBKEY_HEX);
    auto wrapper = hex_to_bytes(WRAPPER_HEX);

    // Verify single wrapper first
    cout << "=== Single Wrapper Verification ===\n";
    auto single_result = verify_wrapper(wrapper, pubkey.data());
    cout << "Valid: " << boolalpha << single_result.valid << "\n";
    cout << "DET: " << single_result.det << "\n";
    cout << "Expected DET: " << DET_HEX << "\n";
    cout << "Verification time: " << single_result.verification_time << " ms\n\n";

    if(!single_result.valid || !compare_hex(single_result.det, DET_HEX)) {
        cerr << "ERROR: Single wrapper verification failed!\n";
        return 1;
    }

    // Prepare test data
    const int NUM_VALID = 1000;
    const int NUM_INVALID = 500;

    vector<vector<unsigned char>> wrappers(NUM_VALID, wrapper);

    // Add 500 invalid wrappers
    for(int i = 0; i < NUM_INVALID; i++) {
        vector<unsigned char> corrupted = wrapper;
        corrupted[10] ^= 0xFF; // Flip one byte to break the signature
        wrappers.push_back(corrupted);
    }

    // Resize result vector
    vector<VerificationResult> results(wrappers.size());

    // Sequential verification
    cout << "=== Sequential Verification ===\n";
    auto seq_start = high_resolution_clock::now();
    for(size_t i = 0; i < wrappers.size(); i++) {
        results[i] = verify_wrapper(wrappers[i], pubkey.data());
    }
    auto seq_end = high_resolution_clock::now();
    auto seq_time = duration_cast<milliseconds>(seq_end - seq_start).count();

    int valid_count = 0;
    int invalid_count = 0;
    for(const auto& res : results) {
        if(res.valid && compare_hex(res.det, DET_HEX)) {
            valid_count++;
        } else {
            invalid_count++;
        }
    }

    cout << "Valid wrappers: " << valid_count << "/" << wrappers.size() << "\n";
    cout << "Invalid wrappers: " << invalid_count << "\n";
    cout << "Total time: " << seq_time << " ms\n";
    cout << "Verifications/sec: " << (wrappers.size() / (seq_time / 1000.0)) << "\n\n";

    // Parallel verification
    cout << "=== Parallel Verification ===\n";
    cout << "Using " << omp_get_max_threads() << " threads\n";
    
    auto par_start = high_resolution_clock::now();
    #pragma omp parallel for
    for(int i = 0; i < static_cast<int>(wrappers.size()); i++) {
        results[i] = verify_wrapper(wrappers[i], pubkey.data());
    }
    auto par_end = high_resolution_clock::now();
    auto par_time = duration_cast<milliseconds>(par_end - par_start).count();

    valid_count = 0;
    invalid_count = 0;
    for(const auto& res : results) {
        if(res.valid && compare_hex(res.det, DET_HEX)) {
            valid_count++;
        } else {
            invalid_count++;
        }
    }

    cout << "Valid wrappers: " << valid_count << "/" << wrappers.size() << "\n";
    cout << "Invalid wrappers: " << invalid_count << "\n";
    cout << "Total time: " << par_time << " ms\n";
    cout << "Verifications/sec: " << (wrappers.size() / (par_time / 1000.0)) << "\n";
    cout << "Speedup: " << fixed << setprecision(2) 
         << (double)seq_time/par_time << "x\n";
         
 // === Separate Timing for Invalid Wrappers Only ===
vector<vector<unsigned char>> invalid_wrappers(wrappers.begin() + NUM_VALID, wrappers.end());
vector<VerificationResult> invalid_results(NUM_INVALID);

cout << "\n=== Timing Invalid Wrappers Only (Sequential) ===\n";
auto inv_seq_start = high_resolution_clock::now();
for (int i = 0; i < NUM_INVALID; i++) {
    invalid_results[i] = verify_wrapper(invalid_wrappers[i], pubkey.data());
}
auto inv_seq_end = high_resolution_clock::now();
auto inv_seq_time = duration_cast<milliseconds>(inv_seq_end - inv_seq_start).count();

cout << "Time to verify 500 invalid wrappers (sequential): " << inv_seq_time << " ms\n";
cout << "Verifications/sec: " << (NUM_INVALID / (inv_seq_time / 1000.0)) << "\n";

// === Parallel Timing for Invalid Wrappers Only ===
cout << "\n=== Timing Invalid Wrappers Only (Parallel) ===\n";
auto inv_par_start = high_resolution_clock::now();
#pragma omp parallel for
for (int i = 0; i < NUM_INVALID; i++) {
    invalid_results[i] = verify_wrapper(invalid_wrappers[i], pubkey.data());
}
auto inv_par_end = high_resolution_clock::now();
auto inv_par_time = duration_cast<milliseconds>(inv_par_end - inv_par_start).count();

cout << "Time to verify 500 invalid wrappers (parallel): " << inv_par_time << " ms\n";
cout << "Verifications/sec: " << (NUM_INVALID / (inv_par_time / 1000.0)) << "\n";
cout << "Speedup: " << fixed << setprecision(2) 
     << (double)inv_seq_time / inv_par_time << "x\n";    

    return 0;
}
