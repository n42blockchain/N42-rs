#!/bin/bash

# 只提取 [patch.'https://github.com/paradigmxyz/reth.git'] 下每个 path = "" 引号中的内容
paths=$(sed -n '/^\[patch.'"'"'https:\/\/github.com\/paradigmxyz\/reth.git'"'"'\]/,/^\[/ {
                    /path *= *"/ {
                        s/.*path *= *"\([^"]*\)".*/\1/p
                    }
                }' Cargo.toml)
# reth路径
reth_dir="../reth"
patch_path="./patch"
base_version="1.1.1v2"

generate_patch() {
    local source=$1
    local reth_path="$reth_dir/$source"
    mkdir -p "$patch_path/$base_version/$source"
    diff -urN "$reth_path" "$source" > "$patch_path/$base_version/$source/.patch"
    echo "Patch generated for $source"
}

# 定义应用 patch 文件的函数
apply_patch() {
    local source=$1
    local reth_path="$reth_dir/$source"
    local patch_file="$patch_path/$base_version/$source/.patch"

    if [ -f "$patch_file" ]; then
        echo "Applying patch to $reth_path"
        patch < "$patch_file"
        echo "Patch applied to $source"
    else
        echo "No patch file found for $patch_file"
    fi
}

# 定义覆盖 target_path 的函数
overwrite_target() {
    local source=$1
    local reth_path="$reth_dir/$source"

    echo "Overwriting $source with contents of $reth_path"
    rsync -a --delete "$reth_path/" "$source/"
    echo "$source has been overwritten with $reth_path"
}

# 遍历每个路径
for path in $paths; do
    # 构造源路径和目标路径
    source_path="$reth_dir/$path"
    target_path="$path"

    echo "Checking path: $source_path"
    # 检查是否存在 Cargo.toml 文件
    if [ -f "$target_path/Cargo.toml" ]; then
        generate_patch "$target_path"
    else
        # 如果没有 Cargo.toml，遍历子文件夹
        echo "No Cargo.toml in $target_path, checking subdirectories..."

        # 遍历子目录并检查
        for sub_dir in "$target_path"/*; do
            if [ -d "$sub_dir" ]; then
                # 如果是目录，检查是否有 Cargo.toml 文件
                if [ -f "$sub_dir/Cargo.toml" ]; then
                    generate_patch "$sub_dir"
                fi
            fi
        done
    fi
done

