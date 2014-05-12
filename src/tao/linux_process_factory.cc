//  File: process_factory.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A factory that creates child processes.
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include "tao/linux_process_factory.h"

#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/resource.h>

#include <algorithm>

#include <glog/logging.h>

#include "tao/pipe_factory.h"
#include "tao/tao_rpc.h"
#include "tao/util.h"

namespace tao {
bool LinuxProcessFactory::MakeHostedProgramSubprin(int id, const string &path,
                                                   string *subprin) const {
  // TODO(kwalsh) Nice toc-tou error here... maybe copy binary to temp file?
  string prog_hash;
  if (!Sha256FileHash(path, &prog_hash)) {
    LOG(ERROR) << "Could not compute the program digest";
    return false;
  }
  subprin->assign(FormatHostedProgramSubprin(id, bytesToHex(prog_hash)));
  return true;
}

bool LinuxProcessFactory::StartHostedProgram(
    const PipeFactory &child_channel_factory, const string &path,
    const list<string> &args, const string &subprin,
    scoped_ptr<HostedLinuxProcess> *child) const {

  scoped_ptr<FDMessageChannel> channel_to_parent, channel_to_child;
  if (!child_channel_factory.CreateChannelPair(&channel_to_parent,
                                                &channel_to_child)) {
    LOG(ERROR) << "Could not create channel for hosted program";
    return false;
  }

  string child_channel_params;
  if (!channel_to_parent->SerializeToString(&child_channel_params)) {
    LOG(ERROR) << "Could not encode child channel parameters";
    return false;
  }

  int child_pid = fork();
  if (child_pid == -1) {
    LOG(ERROR) << "Could not fork hosted program";
    return false;
  }

  if (child_pid == 0) {
    int argc = 1 + (int)args.size() + 1;
    char **argv = new char *[argc + 1];  // +1 for null at end
    int i = 0;
    argv[i++] = strdup(path.c_str());
    for (const string &arg : args) {
      argv[i++] = strdup(arg.c_str());
    }
    // TODO(kwalsh) maybe put channel_params in env instead?
    argv[i++] = strdup(child_channel_params.c_str());
    argv[i++] = nullptr;

    channel_to_child->Close();

    close(STDIN_FILENO);
    dup2(open("/dev/null", O_RDONLY), STDIN_FILENO);

    list<int> keep_open;
    if (!channel_to_parent->GetFileDescriptors(&keep_open)) {
      LOG(ERROR) << "Could not get file descriptors for channel to parent";
      exit(1);
      /* never reached */
    }
    keep_open.push_back(STDIN_FILENO);
    keep_open.push_back(STDOUT_FILENO);
    keep_open.push_back(STDERR_FILENO);
    if (!CloseAllFileDescriptorsExcept(keep_open)) {
      LOG(ERROR) << "Could not clean up file descriptors";
      exit(1);
      /* never reached */
    }

    int rv = execv(path.c_str(), argv);
    if (rv == -1) {
      PLOG(ERROR) << "Could not exec " << path;
      exit(1);
    }
    /* never reached */
    CHECK(false);
    return false;
  } else {
    channel_to_parent->Close();

    child->reset(new HostedLinuxProcess);
    (*child)->subprin = subprin;
    (*child)->pid = child_pid;
    (*child)->channel.reset(channel_to_child.release());
    return true;
  }
}

// TODO(kwalsh) Replace this with formula formatting routines
string LinuxProcessFactory::FormatHostedProgramSubprin(
    int id, const string &prog_hash) const {
  stringstream out;
  if (id != 0)
    out << "Process(" << id << ", ";
  else
    out << "Program(";
  out << quotedString(prog_hash) << ")";
  return out.str();
}

// TODO(kwalsh) Replace this with formula parsing routines
bool LinuxProcessFactory::ParseHostedProgramSubprin(string subprin, int *id,
                                               string *prog_hash,
                                               string *extension) const {
  stringstream in(subprin);
  if (subprin.substr(0, 8) == "Program(") {
    skip(in, "Program(");
    *id = 0;
    getQuotedString(in, prog_hash);
    skip(in, ")");
  } else {
    skip(in, "Process(");
    in >> *id;
    skip(in, ", ");
    getQuotedString(in, prog_hash);
    skip(in, ")");
  }

  string remaining;
  if (in && getline(in, remaining, '\0') && remaining != "") {
    in.str(remaining);
    skip(in, "::");
    getline(in, remaining, '\0');
    extension->assign(remaining);
  } else {
    extension->assign("");
  }

  if (in.bad()) {
    LOG(ERROR) << "Could not parse hosted program subprincipal: " << subprin;
    return false;
  }

  return true;
}

static bool CloseExcept(int fd, const list<int> &keep_open) {
  if (std::find(keep_open.begin(), keep_open.end(), fd) != keep_open.end()) {
    return true;
  } else if (close(fd) < 0 && errno != EBADF) {
    PLOG(ERROR) << "Could not close fd " << fd;
    return false;
  } else {
    return true;
  }
}

bool LinuxProcessFactory::CloseAllFileDescriptorsExcept(const list<int> &keep_open)
{
  DIR *dir = opendir("/proc/self/fd");
  int dir_fd = dirfd(dir);
  if (dir != nullptr) {
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
      if (entry->d_name[0] == '.') continue;
      char *end = nullptr;
      errno = 0;
      long n = strtol(entry->d_name, &end, 10);
      if (errno != 0) {
        PLOG(ERROR) << "Error enumerating /proc/self/fd";
        closedir(dir);
        return false;
      } else if (end == nullptr || end == entry->d_name || end[0] != '\0' ||
                 n < 0 || n > INT_MAX) {
        LOG(ERROR) << "Error enumerating /proc/self/fd";
        closedir(dir);
        return false;
      }
      int fd = static_cast<int>(n);
      if (fd != dir_fd && !CloseExcept(fd, keep_open)) {
        closedir(dir);
        return false;
      }
    }
    closedir(dir);
    return true;
  } else {
    struct rlimit limits;
    if (getrlimit(RLIMIT_NOFILE, &limits) < 0) {
      LOG(ERROR) << "Could not get rlimits";
      return false;
    }
    for (int fd = 0; fd < static_cast<int>(limits.rlim_max); fd++) {
      if (fd != dir_fd && !CloseExcept(fd, keep_open)) {
        closedir(dir);
        return false;
      }
    }
    return true;
  }
}

}  // namespace tao