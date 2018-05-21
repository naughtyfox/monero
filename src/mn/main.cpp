#include <iostream>
#include <vector>
#include <unordered_set>
#include <numeric>
#include <iterator>
#include <algorithm>

#include "crypto/crypto.h"
#include "string_tools.h"
#include "ringct/rctOps.h"

struct keys {
    crypto::public_key pub;
    crypto::secret_key sec;

    std::vector<crypto::public_key> keys;
};

crypto::public_key mult(const crypto::secret_key& sec1, const crypto::secret_key& sec2, const crypto::public_key& pub) {
    return rct::rct2pk(rct::scalarmultKey(rct::scalarmultKey(rct::pk2rct(pub), rct::sk2rct(sec2)), rct::sk2rct(sec1)));
}

crypto::public_key mult(const crypto::secret_key& sec, const crypto::public_key& pub) {
    return rct::rct2pk(rct::scalarmultKey(rct::pk2rct(pub), rct::sk2rct(sec)));
}

void printCombinations(const std::vector<keys>& ws, size_t m, size_t n);
crypto::secret_key restoreKey(const std::vector<keys>& ws, const std::vector<size_t>& indices);
void keyExchangeRound(std::vector<keys>& ws);

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: ./prog m n" << std::endl;
        return 1;
    }

    size_t m = std::atoi(argv[1]);
    size_t n = std::atoi(argv[2]);

    std::vector<keys> ws(n);

    for (size_t i = 0; i < ws.size(); ++i) {
        auto& w = ws[i];
        crypto::generate_keys(w.pub, w.sec);
        w.keys.push_back(w.pub);
        std::cout << "b" << i << ": " << epee::string_tools::pod_to_hex(w.sec) << ", B" << i << ": " << epee::string_tools::pod_to_hex(w.pub) << std::endl;
    }

    for (size_t i = 0; i < (n - m); ++i) {
        keyExchangeRound(ws);
    }

    //getting unique keys
    std::unordered_set<rct::key> uniqKeys;
    for (size_t i = 0; i < ws.size(); ++i) {
        const auto& w = ws[i];
        for (const auto& key: w.keys) {
            if (uniqKeys.insert(rct::pk2rct(key)).second) {
                std::cout << i << " had uniq key" << std::endl;
            }
        }
    }

    rct::key spendPrivate = rct::identity();
    for (const auto& key: uniqKeys) {
        spendPrivate = rct::addKeys(spendPrivate, key);
    }

    std::cout << "spend key: " << epee::string_tools::pod_to_hex(rct::rct2sk(spendPrivate)) << std::endl;
    printCombinations(ws, m, n);

    return 0;
}

void keyExchangeRound(std::vector<keys>& ws) {
    std::vector<std::unordered_set<crypto::public_key>> final(ws.size());
    for (size_t i = 0; i < ws.size(); ++i) {
        const auto& w = ws[i];
        for (size_t j = 0; j < ws.size(); ++j) {
            if (i == j) {
                continue;
            }

            final[j].insert(w.keys.begin(), w.keys.end());
        }
    }

    for (size_t i = 0; i < ws.size(); ++i) {
        for (const auto& key: ws[i].keys) {
            final[i].erase(key);
        }

        ws[i].keys.clear();
        for (const auto& k: final[i]) {
            ws[i].keys.push_back(mult(ws[i].sec, k));
        }
    }
}

class CombinationGenerator {
public:
    CombinationGenerator(size_t n): indices(n) {
        std::iota(indices.begin(), indices.end(), size_t(0));
    }

    void generate(size_t offset, size_t k) {
        if (k == 0) {
            result.push_back(combination);
            return;
        }

        for (size_t i = offset; i <= indices.size() - k; ++i) {
            combination.push_back(indices[i]);
            generate(i+1, k-1);
            combination.pop_back();
        }
    }

    std::vector<std::vector<size_t>> result;
private:
    std::vector<size_t> combination;
    std::vector<size_t> indices;
};

void printCombinations(const std::vector<keys>& ws, size_t m, size_t n) {
    CombinationGenerator g(n);
    g.generate(0, m);

    for (const auto& c: g.result) {
        std::cout << "restored from ";

        std::ostream_iterator<size_t> it(std::cout);
        std::copy(c.begin(), c.end(), it);

        std::cout << ": " << epee::string_tools::pod_to_hex(restoreKey(ws, c)) << std::endl;
    }
}

crypto::secret_key restoreKey(const std::vector<keys>& ws, const std::vector<size_t>& indices) {
    std::unordered_set<rct::key> uniqKeys;

    for (const auto idx: indices) {
        for (const auto& key: ws[idx].keys) {
            uniqKeys.insert(rct::pk2rct(key));
        }
    }

    rct::key spend = rct::identity();
    for (const auto& key: uniqKeys) {
        spend = rct::addKeys(spend, key);
    }

    return rct::rct2sk(spend);
}
