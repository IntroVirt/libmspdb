/*
 * Copyright 2021 Assured Information Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "PDBStore.hh"
#include "file_exception.hh"

#include "builtin_expect.hh"

#include <curl/curl.h>

#include <fcntl.h>
#include <iostream>
#include <regex>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if __GNUC__ >= 8
#include <filesystem>
#else
#include <experimental/filesystem>
using namespace std::experimental;
#endif

using namespace std;

namespace mspdb {

class PDBStore::IMPL {
  public:
    IMPL(const std::string& symbol_store, const std::string& symbol_server_url)
        : symbol_store_dir(symbol_store), symbol_store_lock(symbol_store_dir / ".lock"),
          symbol_server_url(symbol_server_url) {

        filesystem::create_directories(symbol_store_dir);
    }

  public:
    // Check if the PDB filename is valid
    bool pdb_filename_valid(const std::string& pdbIdentifier) const {
        static const std::regex rValidPdbFileName("^[[:alnum:]_-]+\\.pdb$");
        return regex_match(pdbIdentifier, rValidPdbFileName);
    }
    filesystem::path get_pdb_path(const std::string& pdb_filename,
                                  const std::string& pdb_identifier) {
        filesystem::path path{symbol_store_dir};
        path /= pdb_filename;
        path /= pdb_identifier;
        path /= pdb_filename;
        return path;
    }
    bool fetch_pdb(const filesystem::path& pdb_path, const std::string& pdb_identifier) {
        const std::string pdb_filename = pdb_path.filename().string();
        const std::string url =
            symbol_server_url + pdb_filename + "/" + pdb_identifier + "/" + pdb_filename;

        // Create the destination folder
        filesystem::create_directories(pdb_path.parent_path());

        // Download the file
        return download_file(url, pdb_path);
    }

  private:
    bool download_file(const std::string& url, const filesystem::path& path) const {
        std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(),
                                                                 curl_easy_cleanup);
        if (unlikely(!curl)) {
            return false;
        }

        // Create a temp path for the download
        std::string tmpfilename = "." + path.filename().string();
        filesystem::path tmppath = path;
        tmppath.remove_filename() /= tmpfilename;

        // Curl needs a FILE*, so we have to use this c-style fopen
        std::unique_ptr<FILE, decltype(&fclose)> tmpfile(fopen(tmppath.c_str(), "we"), fclose);
        if (!tmpfile) {
            std::cerr << "Failed to open temp file during pdb download\n";
            return false;
        }

        char errbuf[CURL_ERROR_SIZE];
        curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, tmpfile.get());
        curl_easy_setopt(curl.get(), CURLOPT_ERRORBUFFER, &errbuf);
        curl_easy_setopt(curl.get(), CURLOPT_FOLLOWLOCATION, 1);
        curl_easy_setopt(curl.get(), CURLOPT_FAILONERROR, 1);

        CURLcode result = curl_easy_perform(curl.get());
        if (unlikely(result != CURLE_OK)) {
            std::cerr << "Failed to download " << url << ": " << curl_easy_strerror(result) << '\n';
            filesystem::remove(filesystem::path(path));
            return false;
        }

        // Move the temp file to the new file
        filesystem::rename(tmppath, path);

        return true;
    }

  public:
    const filesystem::path symbol_store_dir;
    const filesystem::path symbol_store_lock;
    const std::string symbol_server_url;
};

class FileLock {
  public:
    FileLock(const std::string& path) {
        fd = open(path.c_str(), O_CREAT, 0660);
        if (unlikely(fd < 0)) {
            throw file_exception("Failed to open PDBStore lock file", errno);
        }
        if (unlikely(flock(fd, LOCK_EX))) {
            throw file_exception("Failed to lock on PDBStore lock file", errno);
        }
    }
    ~FileLock() {
        flock(fd, LOCK_UN);
        close(fd);
    }

  private:
    int fd;
};

std::unique_ptr<PDB> PDBStore::open_pdb(const std::string& pdb_filename,
                                        const std::string& pdb_identifier) {
    if (unlikely(!pImpl->pdb_filename_valid(pdb_filename)))
        return nullptr;

    // Acquire the lock, so two processes won't simultaneously try to download a PDB
    FileLock file_lock(pImpl->symbol_store_lock.string());

    filesystem::path pdb_path = pImpl->get_pdb_path(pdb_filename, pdb_identifier);
    if (!filesystem::exists(pdb_path)) {
        // Download the PDB from the symbol server
        if (unlikely(!pImpl->fetch_pdb(pdb_path, pdb_identifier))) {
            return nullptr;
        }
    }

    return std::make_unique<PDB>(pdb_path.string());
}

PDBStore::PDBStore(const std::string& symbol_store_dir)
    : PDBStore(symbol_store_dir, "http://msdl.microsoft.com/download/symbols/") {}

PDBStore::PDBStore(const std::string& symbol_store_dir, const std::string& symbol_server_url)
    : pImpl(std::make_unique<IMPL>(symbol_store_dir, symbol_server_url)) {}

PDBStore::~PDBStore() = default;

} /* namespace mspdb */
