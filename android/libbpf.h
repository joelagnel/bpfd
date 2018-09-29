/*
 * Copyright (C) 2018 The Android Open Source Project
 * Android BPF library - public API
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef BPF_BPFMAP_H
#define BPF_BPFMAP_H

#include <linux/bpf.h>
#include <functional>
#include "libbpf_bcc.h"

// Prototypes of map filter functions
#define filter_key_t const std::function<int(const Key &key, const BpfMap<Key, Value> &map)>
#define filter_key_val_t \
 const std::function<int(const Key &key, const Value &value, const BpfMap<Key, Value> &map)>

#if 0
#include <utils/Log.h>
#include "bpf/BpfUtils.h"
#include "netdutils/Status.h"
#include "netdutils/StatusOr.h"
#endif

#define ALOGE(...)

namespace android {
namespace bpf {

// BPF loader implementation. Loads an eBPF ELF object
int load_prog(const char *elfpath);

// This is a class wrapper for eBPF maps. The eBPF map is a special in-kernel
// data structure that stores data in <Key, Value> pairs. It can be read/write
// from userspace by passing syscalls with the map file descriptor. This class
// is used to generalize the procedure of interacting with eBPF maps and hide
// the implementation detail from other process. Besides the basic syscalls
// wrapper, it also provides some useful helper functions as well as an iterator
// nested class to iterate the map more easily.
//
// NOTE: A kernel eBPF map may be accessed by both kernel and userspace
// processes at the same time. Or if the map is pinned as a virtual file, it can
// be obtained by multiple eBPF map class object and and accessed concurrently.
// Though the map class object and the underlying kernel map are thread safe, it
// is not safe to iterate over a map while another thread or process is deleting
// from it. In this case the iteration can return duplicate entries.
template <class Key, class Value>
class BpfMap {
    public:
        BpfMap<Key, Value>() : mMapFd(-1){};
        BpfMap<Key, Value>(int fd) : mMapFd(fd){};
        BpfMap<Key, Value>(std::string pin_path) {
            int ret = bpf_obj_get(pin_path.c_str());
            if (ret < 0)
                throw new std::runtime_error("Cannot open pinned map location.");

            mPinnedPath = pin_path;
            mMapFd = ret;
        }

        int getMap() const { return mMapFd; };
        bool isValid() const { return mMapFd != -1; }
        const std::string getPinnedPath() const { return mPinnedPath; };

        // Return a pair containing Key and status
        std::pair<Key, int> getFirstKey() const {
            Key firstKey;
            int ret = bpf_get_first_key(mMapFd, &firstKey, sizeof(Key));
            if (ret < 0) { ret = -errno; }

            return std::make_pair(firstKey, ret);
        }

        // Return a pair containing Key and status
        std::pair<Key, int> getNextKey(const Key &key) const {
            Key nextKey;
            int ret = bpf_get_next_key(mMapFd, (void *)&key,
                                       (void *)&nextKey);
            if (ret < 0) { ret = -errno; }

            return std::make_pair(nextKey, ret);
        }

        // Return status
        int update(const Key& key, const Value& value, uint64_t flags) const {
            int ret = bpf_update_elem(mMapFd, &key, &value, flags);
            if (ret < 0) return -errno;
            return ret;
        }

        // Return a pair containing Value and status
        std::pair<Value, int> lookup(const Key& key) const {
            Value value;
            int ret = bpf_lookup_elem(mMapFd, &key, &value);
            if (ret < 0) { ret = -errno; }

            return std::make_pair(value, ret);
        }

        // Return status
        int delete_elem(const Key& key) const {
            int ret = bpf_delete_elem(mMapFd, (void *)&key);
            if (ret < 0) return -errno;
            return ret;
        }

        void reset(int fd = -1) {
            mMapFd = -1;
            mPinnedPath.clear();
        }

        // It is only safe to call this method if guaranteed nothing
        // will concurrently iterate over the map in any process.
        int clear() {
            const auto deleteAllEntries = [](const Key& key, const BpfMap<Key, Value>& map) {
                int res = map.delete_elem(key);
                if (res < 0 && res != -ENOENT)
                    ALOGE("Failed to delete map data %s\n", strerror(res.code()));

                return res;
            };
            iterate(deleteAllEntries);
            return 0;
        }

        // Is empty, and status
        std::pair<bool, int> isEmpty() const {
            auto ret = this->getFirstKey();
            // Return error code ENOENT means the map is empty
            if (ret.second == -ENOENT)
                return std::make_pair(true, 0);
            return std::make_pair(false, ret.second);
        }

        int iterate(filter_key_t &filter) const
        {
            std::pair<Key, int> ret = getFirstKey();
            if (ret.second < 0)
                return ret.second;

            while (ret.second == 0) {
                int filter_ret = filter(ret.first, *this);

                if (filter_ret < 0)
                    return filter_ret;

                ret = getNextKey(ret.first);
            }

            if (ret.second == -ENOENT)
                return 0;
            else
                return ret.second;
        }

        int iterateWithValue(filter_key_val_t &filter) const
        {
            std::pair<Key, int> ret = getFirstKey();
            if (ret.second < 0)
                return ret.second;

            while (ret.second == 0) {
                std::pair<Value, int> lookup_ret;

                lookup_ret = lookup(ret.first);
                if (lookup_ret.second < 0)
                    return lookup_ret.second;

                int filter_ret = filter(ret.first, lookup_ret.first, *this);
                if (filter_ret < 0)
                    return filter_ret;

                ret = getNextKey(ret.first);
            }

            if (ret == -ENOENT)
                return 0;
            else
                return ret;
        }

    private:
        int mMapFd;
        std::string mPinnedPath;
};

}
}

#endif

/* vim: set ts=4 sw=4 expandtab : */
