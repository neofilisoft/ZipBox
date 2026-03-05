#pragma once

#include <string>
#include <vector>

namespace winzox::shell {

bool RunShellAddDialog(const std::vector<std::string>& targetPaths);
void RunQuickAddZox(const std::vector<std::string>& targetPaths);
void RunShellBrowse(const std::string& targetPath);
void RunShellExtractFiles(const std::string& targetPath);
void RunShellExtract(const std::string& targetPath, bool extractHere);

} // namespace winzox::shell
