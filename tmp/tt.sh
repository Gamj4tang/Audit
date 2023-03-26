#!/bin/bash

repo_list=(
# "https://github.com/koor00t/DEX_solidity"
# "https://github.com/jw-dream/DEX_solidity"
# "https://github.com/Namryeong-Kim/DEX_Solidity"
# "https://github.com/Gamj4tang/DEX_solidity"
# "https://github.com/kimziwu/DEX_solidity"
"https://github.com/hangi-dreamer/Dex_solidity"
# "https://github.com/2-Sunghoon-Moon/DEX_solidity"
# "https://github.com/jun4n/DEX_solidity"
# "https://github.com/Sophie00Seo/DEX_solidity"
# "https://github.com/seonghwi-lee/Lending-DEX_solidity"
# "https://github.com/dlanaraa/DEX_solidity"
# "https://github.com/hyeon777/DEX_Solidity"
# "https://github.com/siwon-huh/DEX_solidity"
# "https://github.com/jt-dream/Dex_solidity"
)

lending_repo_list=(
"https://github.com/koor00t/Lending_solidity"
"https://github.com/jw-dream/Leding-DEX-solidity"
"https://github.com/Namryeong-Kim/Lending_solidity"
"https://github.com/Gamj4tang/Lending_solidity"
"https://github.com/kimziwu/Lending_solidity"
"https://github.com/hangi-dreamer/Lending_solidity"
"https://github.com/2-Sunghoon-Moon/Lending_solidity"
"https://github.com/jun4n/Lending_solidity"
"https://github.com/Sophie00Seo/Lending_solidity"
"https://github.com/seonghwi-lee/Lending"
"https://github.com/dlanaraa/Lending_solidity"
"https://github.com/hyeon777/Lending_Solidity"
"https://github.com/siwon-huh/Lending_solidity"
)

for repo in "${repo_list[@]}"; do
    username=$(basename $(dirname $repo))
    project=$(basename $repo)
    target_directory="$username/$project"
    # target_directory="$username-dex"
    echo $target_directory

    # mkdir -p $target_directory
    git submodule add $repo $target_directory
done
