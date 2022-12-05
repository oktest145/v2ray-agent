#!/usr/bin/env bash
# 检测区
# -------------------------------------------------------------
# 检查系统
export LANG=en_US.UTF-8

echoContent() {
	case $1 in
	# 红色
	"red")
		# shellcheck disable=SC2154
		${echoType} "\033[31m${printN}$2 \033[0m"
		;;
		# 天蓝色
	"skyBlue")
		${echoType} "\033[1;36m${printN}$2 \033[0m"
		;;
		# 绿色
	"green")
		${echoType} "\033[32m${printN}$2 \033[0m"
		;;
		# 白色
	"white")
		${echoType} "\033[37m${printN}$2 \033[0m"
		;;
	"magenta")
		${echoType} "\033[31m${printN}$2 \033[0m"
		;;
		# 黄色
	"yellow")
		${echoType} "\033[33m${printN}$2 \033[0m"
		;;
	esac
}
checkSystem() {
	if [[ -n $(find /etc -name "redhat-release") ]] || grep </proc/version -q -i "centos"; then
		mkdir -p /etc/yum.repos.d

		if [[ -f "/etc/centos-release" ]];then
			centosVersion=$(rpm -q centos-release | awk -F "[-]" '{print $3}' | awk -F "[.]" '{print $1}')

			if [[ -z "${centosVersion}" ]] && grep </etc/centos-release "release 8"; then
				centosVersion=8
			fi
		fi

		release="centos"
		installType='yum -y install'
		removeType='yum -y remove'
		upgrade="yum update -y --skip-broken"

	elif grep </etc/issue -q -i "debian" && [[ -f "/etc/issue" ]] || grep </etc/issue -q -i "debian" && [[ -f "/proc/version" ]]; then
		if grep </etc/issue -i "8"; then
			debianVersion=8
		fi
		release="debian"
		installType='apt -y install'
		upgrade="apt update"
		removeType='apt -y autoremove'

	elif grep </etc/issue -q -i "ubuntu" && [[ -f "/etc/issue" ]] || grep </etc/issue -q -i "ubuntu" && [[ -f "/proc/version" ]]; then
		release="ubuntu"
		installType='apt -y install'
		upgrade="apt update"
		removeType='apt -y autoremove'
		if grep </etc/issue -q -i "16.";then
			release=
		fi
	fi

	if [[ -z ${release} ]]; then
		echoContent red "\nThis script does not support this system, please give feedback to the developer below\n"
		echoContent yellow "$(cat /etc/issue)"
		echoContent yellow "$(cat /proc/version)"
		exit 0
	fi
}

# 检查CPU提供商
checkCPUVendor() {
	if [[ -n $(which uname) ]]; then
		if [[ "$(uname)" == "Linux" ]];then
			case "$(uname -m)" in
			'amd64' | 'x86_64')
				xrayCoreCPUVendor="Xray-linux-64"
				v2rayCoreCPUVendor="v2ray-linux-64"
				trojanGoCPUVendor="trojan-go-linux-amd64"
			;;
			'armv8' | 'aarch64')
        		xrayCoreCPUVendor="Xray-linux-arm64-v8a"
				v2rayCoreCPUVendor="v2ray-linux-arm64-v8a"
				trojanGoCPUVendor="trojan-go-linux-armv8"
        	;;
			*)
        		echo "  Do not support this CPU architecture--->"
        		exit 1
        	;;
    		esac
		fi
	else
		echoContent red " Unable to identify this CPU architecture, default AMD64, x86_64--->"
		xrayCoreCPUVendor="Xray-linux-64"
		v2rayCoreCPUVendor="v2ray-linux-64"
		trojanGoCPUVendor="trojan-go-linux-amd64"
	fi
}

# 初始化全局变量
initVar() {
	installType='yum -y install'
	removeType='yum -y remove'
	upgrade="yum -y update"
	echoType='echo -e'

	# 核心支持的cpu版本
	xrayCoreCPUVendor=""
	v2rayCoreCPUVendor=""
	trojanGoCPUVendor=""
	# 域名
	domain=

	# CDN节点的address
	add=

	# 安装总进度
	totalProgress=1

	# 1.xray-core安装
	# 2.v2ray-core 安装
	# 3.v2ray-core[xtls] 安装
	coreInstallType=

	# 核心安装path
	# coreInstallPath=

	# v2ctl Path
	ctlPath=
	# 1.全部安装
	# 2.个性化安装
	# v2rayAgentInstallType=

	# 当前的个性化安装方式 01234
	currentInstallProtocolType=

	# 前置类型
	frontingType=

	# 选择的个性化安装方式
	selectCustomInstallType=

	# v2ray-core、xray-core配置文件的路径
	configPath=

	# 配置文件的path
	currentPath=

	# 配置文件的host
	currentHost=

	# 安装时选择的core类型
	selectCoreType=

	# 默认core版本
	v2rayCoreVersion=

	# 随机路径
	customPath=

	# centos version
	centosVersion=

	# UUID
	currentUUID=

	# pingIPv6 pingIPv4
	# pingIPv4=
	pingIP=
	pingIPv6=

	# 集成更新证书逻辑不再使用单独的脚本--RenewTLS
	renewTLS=$1
}

# 检测安装方式
readInstallType() {
	coreInstallType=
	configPath=

	# 1.检测安装目录
	if [[ -d "/etc/v2ray-agent" ]]; then
		# 检测安装方式 v2ray-core
		if [[ -d "/etc/v2ray-agent/v2ray" && -f "/etc/v2ray-agent/v2ray/v2ray" && -f "/etc/v2ray-agent/v2ray/v2ctl" ]]; then
			if [[ -d "/etc/v2ray-agent/v2ray/conf" && -f "/etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json" ]]; then
				configPath=/etc/v2ray-agent/v2ray/conf/

				if ! grep </etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json -q xtls; then
					# 不带XTLS的v2ray-core
					coreInstallType=2
					# coreInstallPath=/etc/v2ray-agent/v2ray/v2ray
					ctlPath=/etc/v2ray-agent/v2ray/v2ctl
				elif grep </etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json -q xtls; then
					# 带XTLS的v2ray-core
					# coreInstallPath=/etc/v2ray-agent/v2ray/v2ray
					ctlPath=/etc/v2ray-agent/v2ray/v2ctl
					coreInstallType=3
				fi
			fi
		fi

		if [[ -d "/etc/v2ray-agent/xray" && -f "/etc/v2ray-agent/xray/xray" ]]; then
			# 这里检测xray-core
			if [[ -d "/etc/v2ray-agent/xray/conf" ]] && [[ -f "/etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json" || -f "/etc/v2ray-agent/xray/conf/02_trojan_TCP_inbounds.json" ]]; then
				# xray-core
				configPath=/etc/v2ray-agent/xray/conf/
				# coreInstallPath=/etc/v2ray-agent/xray/xray
				ctlPath=/etc/v2ray-agent/xray/xray
				coreInstallType=1
			fi
		fi
	fi
}

# 读取协议类型
readInstallProtocolType() {
	currentInstallProtocolType=

	while read -r row; do
		if echo ${row} | grep -q 02_trojan_TCP_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'trojan'
			frontingType=02_trojan_TCP_inbounds
		fi
		if echo ${row} | grep -q VLESS_TCP_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'0'
			frontingType=02_VLESS_TCP_inbounds
		fi
		if echo ${row} | grep -q VLESS_WS_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'1'
		fi
		if echo ${row} | grep -q trojan_gRPC_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'2'
		fi
		if echo ${row} | grep -q VMess_WS_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'3'
		fi
		if echo ${row} | grep -q 04_trojan_TCP_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'4'
		fi
		if echo ${row} | grep -q VLESS_gRPC_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'5'
		fi

	done < <(ls ${configPath} | grep inbounds.json | awk -F "[.]" '{print $1}')

#	if [[ -f "/etc/v2ray-agent/trojan/trojan-go" ]] && [[ -f "/etc/v2ray-agent/trojan/config_full.json" ]]; then
#		currentInstallProtocolType=${currentInstallProtocolType}'4'
#	fi
}

# 检查文件目录以及path路径
readConfigHostPathUUID() {
	currentPath=
	currentUUID=
	currentHost=
	currentPort=
	currentAdd=
	# 读取path
	if [[ -n "${configPath}" ]]; then
		local fallback=$(jq -r -c '.inbounds[0].settings.fallbacks[]|select(.path)' ${configPath}${frontingType}.json|head -1)

		local path=$(echo "${fallback}"|jq -r .path|awk -F "[/]" '{print $2}')

		if [[ $(echo "${fallback}"|jq -r .dest) == 31297 ]]; then
			currentPath=$(echo "${path}" | awk -F "[w][s]" '{print $1}')
		elif [[ $(echo "${fallback}"|jq -r .dest) == 31298 ]]; then
			currentPath=$(echo "${path}" | awk -F "[t][c][p]" '{print $1}')
		elif [[ $(echo "${fallback}"|jq -r .dest) == 31299 ]]; then
			currentPath=$(echo "${path}" | awk -F "[v][w][s]" '{print $1}')
		fi
	fi

	if [[ "${coreInstallType}" == "1" ]]; then
		currentHost=$(jq -r .inbounds[0].streamSettings.xtlsSettings.certificates[0].certificateFile ${configPath}${frontingType}.json | awk -F '[t][l][s][/]' '{print $2}' | awk -F '[.][c][r][t]' '{print $1}')
		currentUUID=$(jq -r .inbounds[0].settings.clients[0].id ${configPath}${frontingType}.json)
		currentAdd=$(jq -r .inbounds[0].settings.clients[0].add ${configPath}${frontingType}.json)
		if [[ "${currentAdd}" == "null" ]];then
			currentAdd=${currentHost}
		fi
		currentPort=$(jq .inbounds[0].port ${configPath}${frontingType}.json)

	elif [[ "${coreInstallType}" == "2" || "${coreInstallType}" == "3" ]]; then
		if [[ "${coreInstallType}" == "3" ]]; then
			currentHost=$(jq -r .inbounds[0].streamSettings.xtlsSettings.certificates[0].certificateFile ${configPath}${frontingType}.json | awk -F '[t][l][s][/]' '{print $2}' | awk -F '[.][c][r][t]' '{print $1}')
		else
			currentHost=$(jq -r .inbounds[0].streamSettings.tlsSettings.certificates[0].certificateFile ${configPath}${frontingType}.json | awk -F '[t][l][s][/]' '{print $2}' | awk -F '[.][c][r][t]' '{print $1}')
		fi
		currentAdd=$(jq -r .inbounds[0].settings.clients[0].add ${configPath}${frontingType}.json)

		if [[ "${currentAdd}" == "null" ]];then
			currentAdd=${currentHost}
		fi
		currentUUID=$(jq -r .inbounds[0].settings.clients[0].id ${configPath}${frontingType}.json)
		currentPort=$(jq .inbounds[0].port ${configPath}${frontingType}.json)
	fi
}

# 状态展示
showInstallStatus() {
	if [[ -n "${coreInstallType}" ]]; then
		if [[ "${coreInstallType}" == 1 ]]; then
			if [[ -n $(pgrep -f xray/xray) ]]; then
				echoContent yellow "\ncore：Xray-core[In operation]"
			else
				echoContent yellow "\n核心：Xray-core[未运行]"
			fi

		elif [[ "${coreInstallType}" == 2 || "${coreInstallType}" == 3 ]]; then
			if [[ -n $(pgrep -f v2ray/v2ray) ]]; then
				echoContent yellow "\n核心：v2ray-core[运行中]"
			else
				echoContent yellow "\n核心：v2ray-core[未运行]"
			fi
		fi
		# 读取协议类型
		readInstallProtocolType

		if [[ -n ${currentInstallProtocolType} ]]; then
			echoContent yellow "已安装协议：\c"
		fi
		if echo ${currentInstallProtocolType} | grep -q 0; then
			if [[ "${coreInstallType}" == 2 ]]; then
				echoContent yellow "VLESS+TCP[TLS] \c"
			else
				echoContent yellow "VLESS+TCP[TLS/XTLS] \c"
			fi
		fi

		if echo ${currentInstallProtocolType} | grep -q trojan; then
			if [[ "${coreInstallType}" == 1 ]]; then
				echoContent yellow "Trojan+TCP[TLS/XTLS] \c"
			fi
		fi

		if echo ${currentInstallProtocolType} | grep -q 1; then
			echoContent yellow "VLESS+WS[TLS] \c"
		fi

		if echo ${currentInstallProtocolType} | grep -q 2; then
			echoContent yellow "Trojan+gRPC[TLS] \c"
		fi

		if echo ${currentInstallProtocolType} | grep -q 3; then
			echoContent yellow "VMess+WS[TLS] \c"
		fi

		if echo ${currentInstallProtocolType} | grep -q 4; then
			echoContent yellow "Trojan+TCP[TLS] \c"
		fi

		if echo ${currentInstallProtocolType} | grep -q 5; then
			echoContent yellow "VLESS+gRPC[TLS] \c"
		fi
	fi
}

# 清理旧残留
cleanUp() {
	if [[ "$1" == "v2rayClean" ]]; then
		rm -rf "$(find /etc/v2ray-agent/v2ray/* | grep -E '(config_full.json|conf)')"
		handleV2Ray stop >/dev/null
		rm -f /etc/systemd/system/v2ray.service
	elif [[ "$1" == "xrayClean" ]]; then
		rm -rf "$(find /etc/v2ray-agent/xray/* | grep -E '(config_full.json|conf)')"
		handleXray stop >/dev/null
		rm -f /etc/systemd/system/xray.service

	elif [[ "$1" == "v2rayDel" ]]; then
		rm -rf /etc/v2ray-agent/v2ray/*

	elif [[ "$1" == "xrayDel" ]]; then
		rm -rf /etc/v2ray-agent/xray/*
	fi
}

initVar $1
checkSystem
checkCPUVendor
readInstallType
readInstallProtocolType
readConfigHostPathUUID

# -------------------------------------------------------------

# 初始化安装目录
mkdirTools() {
	mkdir -p /etc/v2ray-agent/tls
	mkdir -p /etc/v2ray-agent/subscribe
	mkdir -p /etc/v2ray-agent/subscribe_tmp
	mkdir -p /etc/v2ray-agent/v2ray/conf
	mkdir -p /etc/v2ray-agent/xray/conf
	mkdir -p /etc/v2ray-agent/trojan
	mkdir -p /etc/systemd/system/
	mkdir -p /tmp/v2ray-agent-tls/
}

# 安装工具包
installTools() {
	echo 'Installation tool'
	echoContent skyBlue "\n进度  $1/${totalProgress} : 安装工具"
	# 修复ubuntu个别系统问题
	if [[ "${release}" == "ubuntu" ]]; then
		dpkg --configure -a
	fi

	if [[ -n $(pgrep -f "apt") ]]; then
		pgrep -f apt | xargs kill -9
	fi

	echoContent green " ---> Check, install and update [The new machine will be slow, if there is no response for a long time, please re -execute it manually after stopping]"

	${upgrade} >/dev/null 2>&1
	if [[ "${release}" == "centos" ]]; then
		rm -rf /var/run/yum.pid
		${installType} epel-release >/dev/null 2>&1
	fi

	#	[[ -z `find /usr/bin /usr/sbin |grep -v grep|grep -w curl` ]]

	if ! find /usr/bin /usr/sbin | grep -q -w wget; then
		echoContent green " ---> 安装wget"
		${installType} wget >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w curl; then
		echoContent green " ---> 安装curl"
		${installType} curl >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w unzip; then
		echoContent green " ---> 安装unzip"
		${installType} unzip >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w socat; then
		echoContent green " ---> 安装socat"
		${installType} socat >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w tar; then
		echoContent green " ---> 安装tar"
		${installType} tar >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w cron; then
		echoContent green " ---> 安装crontabs"
		if [[ "${release}" == "ubuntu" ]] || [[ "${release}" == "debian" ]]; then
			${installType} cron >/dev/null 2>&1
		else
			${installType} crontabs >/dev/null 2>&1
		fi
	fi
	if ! find /usr/bin /usr/sbin | grep -q -w jq; then
		echoContent green " ---> 安装jq"
		${installType} jq >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w binutils; then
		echoContent green " ---> 安装binutils"
		${installType} binutils >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w ping6; then
		echoContent green " ---> 安装ping6"
		${installType} inetutils-ping >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w qrencode; then
		echoContent green " ---> 安装qrencode"
		${installType} qrencode >/dev/null 2>&1
	fi

    if ! find /usr/bin /usr/sbin | grep -q -w sudo; then
		echoContent green " ---> 安装sudo"
		${installType} sudo >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w lsb-release; then
		echoContent green " ---> 安装lsb-release"
		${installType} lsb-release >/dev/null 2>&1
	fi

	# 检测nginx版本，并提供是否卸载的选项

	if ! find /usr/bin /usr/sbin | grep -q -w nginx; then
		echoContent green " ---> 安装nginx"
		installNginxTools
	else
		nginxVersion=$(nginx -v 2>&1)
		nginxVersion=$(echo "${nginxVersion}" | awk -F "[n][g][i][n][x][/]" '{print $2}' | awk -F "[.]" '{print $2}')
		if [[ ${nginxVersion} -lt 14 ]]; then
			read -r -p "Reading the current nginx version does not support gRPC，Will cause installation failure，Whether to uninstall nginx and reinstall it ？[y/n]:" unInstallNginxStatus
			if [[ "${unInstallNginxStatus}" == "y" ]]; then
				${removeType} nginx >/dev/null 2>&1
				echoContent yellow " ---> nginx Uninstall"
				echoContent green " ---> Install nginx"
				installNginxTools >/dev/null 2>&1
			else
				exit 0
			fi
		fi
	fi
	if ! find /usr/bin /usr/sbin | grep -q -w semanage; then
		echoContent green " ---> Install semanage"
		${installType} bash-completion >/dev/null 2>&1

		if [[ "${centosVersion}" == "7" ]]; then
			policyCoreUtils="policycoreutils-python.x86_64"
		elif [[ "${centosVersion}" == "8" ]]; then
			policyCoreUtils="policycoreutils-python-utils-2.9-9.el8.noarch"
		fi

		if [[ -n "${policyCoreUtils}" ]]; then
			${installType} ${policyCoreUtils} >/dev/null 2>&1
		fi
		if [[ -n $(which semanage) ]]; then
			semanage port -a -t http_port_t -p tcp 31300

		fi
	fi

	# todo 关闭防火墙

	if [[ ! -d "$HOME/.acme.sh" ]] || [[ -d "$HOME/.acme.sh" && -z $(find "$HOME/.acme.sh/acme.sh") ]]; then
		echoContent green " ---> 安装acme.sh"
		curl -s https://get.acme.sh | sh -s >/etc/v2ray-agent/tls/acme.log 2>&1
		if [[ ! -d "$HOME/.acme.sh" ]] || [[ -z $(find "$HOME/.acme.sh/acme.sh") ]]; then
			echoContent red "  acme installation failed--->"
			tail -n 100 /etc/v2ray-agent/tls/acme.log
			echoContent yellow "Error："
			echoContent red "  1.Obtaining the GitHub file failed, please wait for gitub to try it after recovery. You can view the progress of recovery [https://www.githubstatus.com/]"
			echoContent red "  2.acme.shBUG appears in the script, you can view it[https://github.com/acmesh-official/acme.sh] issues"
			exit 0
		fi
	fi
}

# 安装Nginx
installNginxTools() {

	if [[ "${release}" == "debian" ]]; then
		# 卸载原有Nginx
		# sudo apt remove nginx nginx-common nginx-full -y >/dev/null
		sudo apt install gnupg2 ca-certificates lsb-release -y >/dev/null 2>&1
		echo "deb http://nginx.org/packages/mainline/debian $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list >/dev/null 2>&1
		echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | sudo tee /etc/apt/preferences.d/99nginx >/dev/null 2>&1
		curl -o /tmp/nginx_signing.key https://nginx.org/keys/nginx_signing.key >/dev/null 2>&1
		# gpg --dry-run --quiet --import --import-options import-show /tmp/nginx_signing.key
		sudo mv /tmp/nginx_signing.key /etc/apt/trusted.gpg.d/nginx_signing.asc
		sudo apt update >/dev/null 2>&1

	elif [[ "${release}" == "ubuntu" ]]; then
		# 卸载原有Nginx
		# sudo apt remove nginx nginx-common nginx-full -y >/dev/null
		sudo apt install gnupg2 ca-certificates lsb-release -y >/dev/null 2>&1
		echo "deb http://nginx.org/packages/mainline/ubuntu $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list >/dev/null 2>&1
		echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | sudo tee /etc/apt/preferences.d/99nginx >/dev/null 2>&1
		curl -o /tmp/nginx_signing.key https://nginx.org/keys/nginx_signing.key >/dev/null 2>&1
		# gpg --dry-run --quiet --import --import-options import-show /tmp/nginx_signing.key
		sudo mv /tmp/nginx_signing.key /etc/apt/trusted.gpg.d/nginx_signing.asc
		sudo apt update >/dev/null 2>&1

	elif [[ "${release}" == "centos" ]]; then
		${installType} yum-utils >/dev/null 2>&1
		cat <<EOF >/etc/yum.repos.d/nginx.repo
[nginx-stable]
name=nginx stable repo
baseurl=http://nginx.org/packages/centos/\$releasever/\$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true

[nginx-mainline]
name=nginx mainline repo
baseurl=http://nginx.org/packages/mainline/centos/\$releasever/\$basearch/
gpgcheck=1
enabled=0
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
EOF
		sudo yum-config-manager --enable nginx-mainline >/dev/null 2>&1
	fi
	${installType} nginx >/dev/null 2>&1
	systemctl daemon-reload
	systemctl enable nginx
}

# 安装warp
installWarp(){
    ${installType} gnupg2 -y >/dev/null 2>&1
	if [[ "${release}" == "debian" ]]; then
		curl -s https://pkg.cloudflareclient.com/pubkey.gpg | sudo apt-key add - >/dev/null 2>&1
		echo "deb http://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null 2>&1
		sudo apt update >/dev/null 2>&1

	elif [[ "${release}" == "ubuntu" ]]; then
		curl -s https://pkg.cloudflareclient.com/pubkey.gpg | sudo apt-key add - >/dev/null 2>&1
		echo "deb http://pkg.cloudflareclient.com/ focal main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null 2>&1
		sudo apt update >/dev/null 2>&1

	elif [[ "${release}" == "centos" ]]; then
		${installType} yum-utils >/dev/null 2>&1
		sudo rpm -ivh http://pkg.cloudflareclient.com/cloudflare-release-el${centosVersion}.rpm >/dev/null 2>&1
	fi

	echoContent green " ---> 安装WARP"
	${installType} cloudflare-warp >/dev/null 2>&1
	if [[ -z $(which warp-cli) ]];then
        echoContent red " ---> 安装WARP失败"
        exit 0;
	fi
	systemctl enable warp-svc
	warp-cli --accept-tos register
	warp-cli --accept-tos set-mode proxy
	warp-cli --accept-tos set-proxy-port 31303
	warp-cli --accept-tos connect
#	if [[]];then
#	fi
    # todo curl --socks5 127.0.0.1:31303 https://www.cloudflare.com/cdn-cgi/trace
	# systemctl daemon-reload
	# systemctl enable cloudflare-warp
}
# 初始化Nginx申请证书配置
initTLSNginxConfig() {
	handleNginx stop
	echoContent skyBlue "\nschedule  $1/${totalProgress} : Initialize nginx application certificate configuration"
	if [[ -n "${currentHost}" ]]; then
		echo
		read -r -p "Read the last installation record, whether to use the domain name at the time of the last installation ？[y/n]:" historyDomainStatus
		if [[ "${historyDomainStatus}" == "y" ]]; then
			domain=${currentHost}
			echoContent yellow "\n ---> 域名：${domain}"
		else
			echo
			echoContent yellow "Please enter the domain name to be configured：www.v2ray-agent.com --->"
			read -r -p "domain name:" domain
		fi
	else
		echo
		echoContent yellow "Please enter the domain name to be configured：www.v2ray-agent.com --->"
		read -r -p "domain name:" domain
	fi

	if [[ -z ${domain} ]]; then
		echoContent red "  The domain name should not be empty--->"
		initTLSNginxConfig
	else
		# 修改配置
		echoContent green "\n ---> ConfigurationNginx"
		touch /etc/nginx/conf.d/alone.conf
		echo "server {listen 80;listen [::]:80;server_name ${domain};root /usr/share/nginx/html;location ~ /.well-known {allow all;}location /test {return 200 'fjkvymb6len';}}" >/etc/nginx/conf.d/alone.conf
		# 启动nginx
		handleNginx start
		echoContent yellow "\nCheck whether the IP is set to the currentVPS"
		checkIP
		# 测试nginx
		echoContent yellow "\nCheck if nginx is normal"
		sleep 0.5
		domainResult=$(curl -s "${domain}/test" --resolve "${domain}:80:${pingIP}" | grep fjkvymb6len)
		if [[ -n ${domainResult} ]]; then
			handleNginx stop
			echoContent green "\n ---> NginxConfiguration"
		else
			echoContent red " ---> Can't access the server normally, please detect whether the domain name is correct, the DNS analysis of the domain name, and whether the firewall settings are correct--->"
			exit 0
		fi
	fi
}

# 修改nginx重定向配置
updateRedirectNginxConf() {

	cat <<EOF >/etc/nginx/conf.d/alone.conf
server {
	listen 80;
	listen [::]:80;
	server_name ${domain};
	# shellcheck disable=SC2154
	return 301 https://${domain}$request_uri;
}
server {
		listen 127.0.0.1:31300;
		server_name _;
		return 403;
}
EOF
if [[ -n $(echo "${selectCustomInstallType}" |grep 2) && -n $(echo "${selectCustomInstallType}" |grep 5) ]] || [[ -z "${selectCustomInstallType}" ]];then

		cat <<EOF >>/etc/nginx/conf.d/alone.conf
server {
	listen 127.0.0.1:31302 http2;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/ {
    		add_header Content-Type text/plain;
    		alias /etc/v2ray-agent/subscribe/;
    }

    location /${currentPath}grpc {
		client_max_body_size 0;
#		keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31301;
	}

	location /${currentPath}trojangrpc {
		client_max_body_size 0;
		# keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31304;
	}
}
EOF
	elif echo "${selectCustomInstallType}" |grep -q 5 || [[ -z "${selectCustomInstallType}" ]]; then
		cat <<EOF >>/etc/nginx/conf.d/alone.conf
server {
	listen 127.0.0.1:31302 http2;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/ {
    		add_header Content-Type text/plain;
    		alias /etc/v2ray-agent/subscribe/;
    }
	location /${currentPath}grpc {
		client_max_body_size 0;
#		keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31304;
	}
}
EOF

	elif echo "${selectCustomInstallType}" |grep -q 2 || [[ -z "${selectCustomInstallType}" ]];then

		cat <<EOF >>/etc/nginx/conf.d/alone.conf
server {
	listen 127.0.0.1:31302 http2;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/ {
    		add_header Content-Type text/plain;
    		alias /etc/v2ray-agent/subscribe/;
    }
	location /${currentPath}trojangrpc {
		client_max_body_size 0;
		# keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31301;
	}
}
EOF
	else

		cat <<EOF >>/etc/nginx/conf.d/alone.conf
server {
	listen 127.0.0.1:31302 http2;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/ {
    		add_header Content-Type text/plain;
    		alias /etc/v2ray-agent/subscribe/;
    }
	location / {
	}
}
EOF
	fi

	cat <<EOF >>/etc/nginx/conf.d/alone.conf
server {
	listen 127.0.0.1:31300;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/ {
		add_header Content-Type text/plain;
		alias /etc/v2ray-agent/subscribe/;
	}
	location / {
		add_header Strict-Transport-Security "max-age=15552000; preload" always;
	}
}
EOF

}

# 检查ip
checkIP() {
	echoContent skyBlue " ---> 检查ipv4中"
	pingIP=$(curl -s -H 'accept:application/dns-json' 'https://cloudflare-dns.com/dns-query?name='${domain}'&type=A' | jq -r ".Answer|.[]|select(.type==1)|.data")

	if [[ -z "${pingIP}" ]]; then
		echoContent skyBlue " ---> 检查ipv6中"
		pingIP=$(curl -s -H 'accept:application/dns-json' 'https://cloudflare-dns.com/dns-query?name='${domain}'&type=AAAA' | jq -r ".Answer|.[]|select(.type==28)|.data")
		pingIPv6=${pingIP}
	fi

	if [[ -n "${pingIP}" ]]; then
		echo
		read -r -p "The current domain name IP is[${pingIP}]，is it right or not[y/n]？" domainStatus
		if [[ "${domainStatus}" == "y" ]]; then
			echoContent green "\n ---> IPConfirm"
		else
			echoContent red "\n ---> 1.an examination Cloudflare DNS Analysis is normal"
			echoContent red " ---> 2.an examination Cloudflare DNS Whether the cloud is gray\n"
			exit 0
		fi
	else
		read -r -p "IP If the query fails, please check whether the domain name is correct and whether to try it out[y/n]？" retryStatus
		if [[ "${retryStatus}" == "y" ]]; then
			checkIP
		else
			exit 0
		fi
	fi
}
# 安装TLS
installTLS() {
	echoContent skyBlue "\n progress  $1/${totalProgress} : Apply for a TLS certificate\n"
	local tlsDomain=${domain}
	# 安装tls
	if [[ -f "/etc/v2ray-agent/tls/${tlsDomain}.crt" && -f "/etc/v2ray-agent/tls/${tlsDomain}.key" && -n $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ]] || [[ -d "$HOME/.acme.sh/${tlsDomain}_ecc" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.key" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.cer" ]]; then
		# 存在证书
		echoContent green " --->Detecting certificate"
		checkTLStatus "${tlsDomain}"
		if [[ "${tlsStatus}" == "expired" ]]; then
			rm -rf $HOME/.acme.sh/${tlsDomain}_ecc/*
			rm -rf /etc/v2ray-agent/tls/${tlsDomain}*
			installTLS "$1"
		else
			echoContent green " ---> Valid certificate"

			if ! ls /etc/v2ray-agent/tls/ | grep -q "${tlsDomain}.crt" || ! ls /etc/v2ray-agent/tls/ | grep -q "${tlsDomain}.key" || [[ -z $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ]]; then
				sudo "$HOME/.acme.sh/acme.sh" --installcert -d "${tlsDomain}" --fullchainpath "/etc/v2ray-agent/tls/${tlsDomain}.crt" --keypath "/etc/v2ray-agent/tls/${tlsDomain}.key" --ecc >/dev/null
			else
				echoContent yellow " ---> If you haven't expired, please choose[n]\n"
				read -r -p "Whether to reinstall？[y/n]:" reInstallStatus
				if [[ "${reInstallStatus}" == "y" ]]; then
					rm -rf /etc/v2ray-agent/tls/*
					installTLS "$1"
				fi
			fi
		fi
	elif [[ -d "$HOME/.acme.sh" ]] && [[ ! -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.cer" || ! -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.key" ]]; then
		echoContent green " ---> Install the TLS certificate"
		if [[ -n "${pingIPv6}" ]]; then
			sudo "$HOME/.acme.sh/acme.sh" --issue -d "${tlsDomain}" --standalone -k ec-256 --server letsencrypt --listen-v6 >> /etc/v2ray-agent/tls/acme.log
		else
			sudo "$HOME/.acme.sh/acme.sh" --issue -d "${tlsDomain}" --standalone -k ec-256 --server letsencrypt >> /etc/v2ray-agent/tls/acme.log
		fi

		if [[ -d "$HOME/.acme.sh/${tlsDomain}_ecc" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.key" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.cer" ]]; then
			sudo "$HOME/.acme.sh/acme.sh" --installcert -d "${tlsDomain}" --fullchainpath "/etc/v2ray-agent/tls/${tlsDomain}.crt" --keypath "/etc/v2ray-agent/tls/${tlsDomain}.key" --ecc >/dev/null
		fi

		if [[ ! -f "/etc/v2ray-agent/tls/${tlsDomain}.crt" || ! -f "/etc/v2ray-agent/tls/${tlsDomain}.key"  ]] || [[ -z $(cat "/etc/v2ray-agent/tls/${tlsDomain}.key") || -z $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ]]; then
			tail -n 10 /etc/v2ray-agent/tls/acme.log
			echoContent red " ---> TLSIf the installation fails, please check the ACME log"
			exit 0
		fi
		echoContent green " ---> TLSSuccessful"
	else
		echoContent yellow " ---> Not Installedacme.sh"
		exit 0
	fi
}
# 配置伪装博客
initNginxConfig() {
	echoContent skyBlue "\nschedule  $1/${totalProgress} : Configuration Nginx"

	cat <<EOF >/etc/nginx/conf.d/alone.conf
server {
    listen 80;
    listen [::]:80;
    server_name ${domain};
    root /usr/share/nginx/html;
    location ~ /.well-known {allow all;}
    location /test {return 200 'fjkvymb6len';}
}
EOF
}

# 自定义/随机路径
randomPathFunction() {
	echoContent skyBlue "\nschedule  $1/${totalProgress} : Generate random path"

	if [[ -n "${currentPath}" ]]; then
		echo
		read -r -p "Read the previous installation record, whether to use the PATH path at the time of the last installation ？[y/n]:" historyPathStatus
		echo
	fi

	if [[ "${historyPathStatus}" == "y" ]]; then
		customPath=${currentPath}
		echoContent green " ---> Successful use\n"
	else
		echoContent yellow "Please enter the custom path [Example: alone]，No oblique, [Enter] Random path"
		read -r -p 'path:' customPath

		if [[ -z "${customPath}" ]]; then
			customPath=$(head -n 50 /dev/urandom | sed 's/[^a-z]//g' | strings -n 4 | tr 'A-Z' 'a-z' | head -1)
			currentPath=${customPath:0:4}
			customPath=${currentPath}
		else
			currentPath=${customPath}
		fi

	fi
	echoContent yellow "\n path：${currentPath}"
	echoContent skyBlue "\n----------------------------"
}
# Nginx伪装博客
nginxBlog() {
	echoContent skyBlue "\nschedule $1/${totalProgress} : Add camouflage site"
	if [[ -d "/usr/share/nginx/html" && -f "/usr/share/nginx/html/check" ]]; then
		echo
		read -r -p "Detecting the installation site, whether to reinstall it[y/n]：" nginxBlogInstallStatus
		if [[ "${nginxBlogInstallStatus}" == "y" ]]; then
			rm -rf /usr/share/nginx/html
			randomNum=$((RANDOM%6+1))
			wget -q -P /usr/share/nginx https://raw.githubusercontent.com/oktest145/v2ray-agent/master/fodder/blog/unable/html${randomNum}.zip >/dev/null
			unzip -o /usr/share/nginx/html${randomNum}.zip -d /usr/share/nginx/html >/dev/null
			rm -f /usr/share/nginx/html${randomNum}.zip*
			echoContent green " ---> Add a camouflage station successfully"
		fi
	else
		randomNum=$((RANDOM%6+1))
		rm -rf /usr/share/nginx/html
		wget -q -P /usr/share/nginx https://raw.githubusercontent.com/oktest145/v2ray-agent/master/fodder/blog/unable/html${randomNum}.zip >/dev/null
		unzip -o /usr/share/nginx/html${randomNum}.zip -d /usr/share/nginx/html >/dev/null
		rm -f /usr/share/nginx/html${randomNum}.zip*
		echoContent green " ---> Add a camouflage station successfully"
	fi

}
# 操作Nginx
handleNginx() {

	if [[ -z $(pgrep -f "nginx") ]] && [[ "$1" == "start" ]]; then
		nginx
		sleep 0.5
		if ! ps -ef | grep -v grep | grep -q nginx; then
			echoContent red " ---> Nginx's launch failed"
			echoContent red " ---> Please try to install nginx manually, and then execute the script again"
			exit 0
		fi
	elif [[ "$1" == "stop" ]] && [[ -n $(pgrep -f "nginx") ]]; then
		nginx -s stop >/dev/null 2>&1
		sleep 0.5
		if [[ -n $(pgrep -f "nginx") ]]; then
			pgrep -f "nginx" | xargs kill -9
		fi
	fi
}

# 定时任务更新tls证书
installCronTLS() {
	echoContent skyBlue "\n progress $1/${totalProgress} : Add regular maintenance certificate"
	crontab -l >/etc/v2ray-agent/backup_crontab.cron
	local historyCrontab=$(sed '/v2ray-agent/d;/acme.sh/d' /etc/v2ray-agent/backup_crontab.cron)
	echo "${historyCrontab}" >/etc/v2ray-agent/backup_crontab.cron
	echo "30 1 * * * /bin/bash /etc/v2ray-agent/install.sh RenewTLS >> /etc/v2ray-agent/crontab_tls.log 2>&1" >>/etc/v2ray-agent/backup_crontab.cron
	crontab /etc/v2ray-agent/backup_crontab.cron
	echoContent green "\n ---> Add regular maintenance certificate"
}

# 更新证书
renewalTLS() {
	echoContent skyBlue "\nProgress 1/1: Update certificate"

	if [[ -d "$HOME/.acme.sh/${currentHost}_ecc" ]] && [[ -f "$HOME/.acme.sh/${currentHost}_ecc/${currentHost}.key" ]] && [[ -f "$HOME/.acme.sh/${currentHost}_ecc/${currentHost}.cer" ]]; then
		modifyTime=$(stat $HOME/.acme.sh/${currentHost}_ecc/${currentHost}.cer | sed -n '7,6p' | awk '{print $2" "$3" "$4" "$5}')

		modifyTime=$(date +%s -d "${modifyTime}")
		currentTime=$(date +%s)
		stampDiff=$(expr ${currentTime} - ${modifyTime})
		days=$(expr ${stampDiff} / 86400)
		remainingDays=$(expr 90 - ${days})
		tlsStatus=${remainingDays}
		if [[ ${remainingDays} -le 0 ]]; then
			tlsStatus="expired"
		fi

		echoContent skyBlue " ---> Certificate inspection date:$(date "+%F %H:%M:%S")"
		echoContent skyBlue " ---> Certificate generation date:$(date -d @"${modifyTime}" +"%F %H:%M:%S")"
		echoContent skyBlue " ---> Certificate generation days:${days}"
		echoContent skyBlue " ---> Certificate remaining days:"${tlsStatus}
		echoContent skyBlue " ---> Automatically update the last day before the certificate expires. If the update fails, please update manually"

		if [[ ${remainingDays} -le 1 ]]; then
			echoContent yellow " ---> Re -generate a certificate"
			handleNginx stop
			sudo "$HOME/.acme.sh/acme.sh" --cron --home "$HOME/.acme.sh"
			sudo "$HOME/.acme.sh/acme.sh" --installcert -d "${currentHost}" --fullchainpath /etc/v2ray-agent/tls/"${currentHost}.crt" --keypath /etc/v2ray-agent/tls/"${currentHost}.key" --ecc
			reloadCore
		else
			echoContent green " ---> Valid certificate"
		fi
	else
		echoContent red " ---> Not Installed"
	fi
}
# 查看TLS证书的状态
checkTLStatus() {

	if [[ -n "$1" ]]; then
		if [[ -d "$HOME/.acme.sh/$1_ecc" ]] && [[ -f "$HOME/.acme.sh/$1_ecc/$1.key" ]] && [[ -f "$HOME/.acme.sh/$1_ecc/$1.cer" ]]; then
			modifyTime=$(stat $HOME/.acme.sh/$1_ecc/$1.key | sed -n '7,6p' | awk '{print $2" "$3" "$4" "$5}')

			modifyTime=$(date +%s -d "${modifyTime}")
			currentTime=$(date +%s)
			stampDiff=$(expr ${currentTime} - ${modifyTime})
			days=$(expr ${stampDiff} / 86400)
			remainingDays=$(expr 90 - ${days})
			tlsStatus=${remainingDays}
			if [[ ${remainingDays} -le 0 ]]; then
				tlsStatus="已过期"
			fi
			echoContent skyBlue " ---> Certificate generation datee -d "@${modifyTime}" +"%F %H:%M:%S")"
			echoContent skyBlue " ---> Certificate of Certificate Generation Date:${days}"
			echoContent skyBlue " ---> Certificate remaining days:${tlsStatus}"
		fi
	fi
}

# 安装V2Ray、指定版本
installV2Ray() {
	readInstallType
	echoContent skyBlue "\nschedule $1/${totalProgress} : Install v2ray"

	if [[ "${coreInstallType}" != "2" && "${coreInstallType}" != "3" ]]; then
		if [[ "${selectCoreType}" == "2" ]]; then

			version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r .[].tag_name|head -1)
		else
			version=${v2rayCoreVersion}
		fi

		echoContent green " ---> v2ray-core版本:${version}"
		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /etc/v2ray-agent/v2ray/ "https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip"
		else
			wget -c -P /etc/v2ray-agent/v2ray/ "https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip" >/dev/null 2>&1
		fi

		unzip -o /etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip -d /etc/v2ray-agent/v2ray >/dev/null
		rm -rf /etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip
	else
		if [[ "${selectCoreType}" == "3" ]]; then
			echoContent green " ---> Lock V2Ray-Core version is v4.32.1"
			rm -f /etc/v2ray-agent/v2ray/v2ray
			rm -f /etc/v2ray-agent/v2ray/v2ctl
			installV2Ray "$1"
		else
			echoContent green " ---> v2ray-coreVersion:$(/etc/v2ray-agent/v2ray/v2ray --version | awk '{print $2}' | head -1)"
			read -r -p "Whether to update and upgrade？[y/n]:" reInstallV2RayStatus
			if [[ "${reInstallV2RayStatus}" == "y" ]]; then
				rm -f /etc/v2ray-agent/v2ray/v2ray
				rm -f /etc/v2ray-agent/v2ray/v2ctl
				installV2Ray "$1"
			fi
		fi
	fi
}

# 安装xray
installXray() {
	readInstallType
	echoContent skyBlue "\n进度  $1/${totalProgress} : InstallXray"

	if [[ "${coreInstallType}" != "1" ]]; then

		version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | jq -r .[].tag_name|head -1)

		echoContent green " ---> Xray-core版本:${version}"
		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /etc/v2ray-agent/xray/ "https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip"
		else
			wget -c -P /etc/v2ray-agent/xray/ "https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip" >/dev/null 2>&1
		fi

		unzip -o /etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip -d /etc/v2ray-agent/xray >/dev/null
		rm -rf /etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip
		chmod 655 /etc/v2ray-agent/xray/xray
	else
		echoContent green " ---> Xray-core版本:$(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)"
		read -r -p "是否更新、升级？[y/n]:" reInstallXrayStatus
		if [[ "${reInstallXrayStatus}" == "y" ]]; then
			rm -f /etc/v2ray-agent/xray/xray
			installXray "$1"
		fi
	fi
}

# 安装Trojan-go
installTrojanGo() {
	echoContent skyBlue "\n进度  $1/${totalProgress} : 安装Trojan-Go"

	if ! ls /etc/v2ray-agent/trojan/ | grep -q trojan-go; then

		version=$(curl -s https://api.github.com/repos/p4gefau1t/trojan-go/releases | jq -r .[0].tag_name)
		echoContent green " ---> Trojan-Go版本:${version}"
		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /etc/v2ray-agent/trojan/ "https://github.com/p4gefau1t/trojan-go/releases/download/${version}/${trojanGoCPUVendor}.zip"
		else
			wget -c -P /etc/v2ray-agent/trojan/ "https://github.com/p4gefau1t/trojan-go/releases/download/${version}/${trojanGoCPUVendor}.zip" >/dev/null 2>&1
		fi
		unzip -o /etc/v2ray-agent/trojan/${trojanGoCPUVendor}.zip -d /etc/v2ray-agent/trojan >/dev/null
		rm -rf /etc/v2ray-agent/trojan/${trojanGoCPUVendor}.zip
	else
		echoContent green " ---> Trojan-Go版本:$(/etc/v2ray-agent/trojan/trojan-go --version | awk '{print $2}' | head -1)"

		read -r -p "是否重新安装？[y/n]:" reInstallTrojanStatus
		if [[ "${reInstallTrojanStatus}" == "y" ]]; then
			rm -rf /etc/v2ray-agent/trojan/trojan-go*
			installTrojanGo "$1"
		fi
	fi
}

# v2ray版本管理
v2rayVersionManageMenu() {
	echoContent skyBlue "\nschedule  $1/${totalProgress} : V2Ray版本管理"
	if [[ ! -d "/etc/v2ray-agent/v2ray/" ]]; then
		echoContent red " ---> noInstallationDirectoryIsDetected,PleaseExecuteTheContentOfTheScript"
		menu
		exit 0
	fi
	echoContent red "\n=============================================================="
	echoContent yellow "1.upgradegrade"
	echoContent yellow "2.go back"
	echoContent yellow "3.Turn off V2ray-core"
	echoContent yellow "4.Open V2ray-core"
	echoContent yellow "5.Restart v2ray-core"
	echoContent red "=============================================================="
	read -r -p "please choose:" selectV2RayType
	if [[ "${selectV2RayType}" == "1" ]]; then
		updateV2Ray
	elif [[ "${selectV2RayType}" == "2" ]]; then
		echoContent yellow "\n1.Only the last five versions of the most nearest can be returned"
		echoContent yellow "2.You can use it normally after you return"
		echoContent yellow "3.If the retreat version does not support the current Config, it will not be connected, and it will operate carefully"
		echoContent skyBlue "------------------------Version-------------------------------"
		curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r .[].tag_name| head -5| awk '{print ""NR""":"$0}'

		echoContent skyBlue "--------------------------------------------------------------"
		read -r -p "Please enter the version to be returned:" selectV2rayVersionType
		version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r .[].tag_name| head -5| awk '{print ""NR""":"$0}' | grep "${selectV2rayVersionType}:" | awk -F "[:]" '{print $2}')
		if [[ -n "${version}" ]]; then
			updateV2Ray ${version}
		else
			echoContent red "\n ---> Input is wrong, please re -enter"
			v2rayVersionManageMenu 1
		fi
	elif [[ "${selectXrayType}" == "3" ]]; then
		handleV2Ray stop
	elif [[ "${selectXrayType}" == "4" ]]; then
		handleV2Ray start
	elif [[ "${selectXrayType}" == "5" ]]; then
		reloadCore
	fi
}

# xray版本管理
xrayVersionManageMenu() {
	echoContent skyBlue "\n进度  $1/${totalProgress} : Xray version management"
	if [[ ! -d "/etc/v2ray-agent/xray/" ]]; then
		echoContent red " ---> No installation directory is detected, please execute the content of the script"
		menu
		exit 0
	fi
	echoContent red "\n=============================================================="
	echoContent yellow "1.upgrade"
	echoContent yellow "2.go back"
	echoContent yellow "3.Turn off xray-core"
	echoContent yellow "4.Open xray-core"
	echoContent yellow "5.Restart xray-core"
	echoContent red "=============================================================="
	read -r -p "please choose:" selectXrayType
	if [[ "${selectXrayType}" == "1" ]]; then
		updateXray
	elif [[ "${selectXrayType}" == "2" ]]; then
		echoContent yellow "\n1.Because xray-Core is frequently updated, only the two most recent versions can be returned"
		echoContent yellow "2.You can use it normally after you return"
		echoContent yellow "3.If the retreat version does not support the current Config, it will not be connected, and it will operate carefully"
		echoContent skyBlue "------------------------Version-------------------------------"
		curl -s https://api.github.com/repos/XTLS/Xray-core/releases | jq -r .[].tag_name| head -2 | awk '{print ""NR""":"$0}'
		echoContent skyBlue "--------------------------------------------------------------"
		read -r -p "Please enter the version to be returned:" selectXrayVersionType
		version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | jq -r .[].tag_name| head -2 | awk '{print ""NR""":"$0}' | grep "${selectXrayVersionType}:" | awk -F "[:]" '{print $2}')
		if [[ -n "${version}" ]]; then
			updateXray "${version}"
		else
			echoContent red "\n ---> Input is wrong, please re -enter"
			xrayVersionManageMenu 1
		fi
	elif [[ "${selectXrayType}" == "3" ]]; then
		handleXray stop
	elif [[ "${selectXrayType}" == "4" ]]; then
		handleXray start
	elif [[ "${selectXrayType}" == "5" ]]; then
		reloadCore
	fi

}
# Update v2ray
updateV2Ray() {
	readInstallType
	if [[ -z "${coreInstallType}" ]]; then

		if [[ -n "$1" ]]; then
			version=$1
		else
			version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r .[0].tag_name)
		fi
		# 使用锁定的版本
		if [[ -n "${v2rayCoreVersion}" ]]; then
			version=${v2rayCoreVersion}
		fi
		echoContent green " ---> v2ray-core版本:${version}"

		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /etc/v2ray-agent/v2ray/ "https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip"
		else
			wget -c -P "/etc/v2ray-agent/v2ray/ https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip" >/dev/null 2>&1
		fi

		unzip -o /etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip -d /etc/v2ray-agent/v2ray >/dev/null
		rm -rf /etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip
		handleV2Ray stop
		handleV2Ray start
	else
		echoContent green " ---> 当前v2ray-core版本:$(/etc/v2ray-agent/v2ray/v2ray --version | awk '{print $2}' | head -1)"

		if [[ -n "$1" ]]; then
			version=$1
		else
			version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r .[0].tag_name)
		fi

		if [[ -n "${v2rayCoreVersion}" ]]; then
			version=${v2rayCoreVersion}
		fi
		if [[ -n "$1" ]]; then
			read -r -p "回退版本为${version},Whether to continue?[y/n]:" rollbackV2RayStatus
			if [[ "${rollbackV2RayStatus}" == "y" ]]; then
				if [[ "${coreInstallType}" == "2" || "${coreInstallType}" == "3" ]]; then
					echoContent green " ---> Current v2ray-core version:$(/etc/v2ray-agent/v2ray/v2ray --version | awk '{print $2}' | head -1)"
				elif [[ "${coreInstallType}" == "1" ]]; then
					echoContent green " ---> Current xray-core版本:$(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)"
				fi

				handleV2Ray stop
				rm -f /etc/v2ray-agent/v2ray/v2ray
				rm -f /etc/v2ray-agent/v2ray/v2ctl
				updateV2Ray "${version}"
			else
				echoContent green " ---> Give up the refund version"
			fi
		elif [[ "${version}" == "v$(/etc/v2ray-agent/v2ray/v2ray --version | awk '{print $2}' | head -1)" ]]; then
			read -r -p "The current version is the same as the latest version. Is it re -installed?[y/n]:" reInstallV2RayStatus
			if [[ "${reInstallV2RayStatus}" == "y" ]]; then
				handleV2Ray stop
				rm -f /etc/v2ray-agent/v2ray/v2ray
				rm -f /etc/v2ray-agent/v2ray/v2ctl
				updateV2Ray
			else
				echoContent green " ---> Give up and reinstall"
			fi
		else
			read -r -p "The latest version is：${version}，Whether to update？[y/n]：" installV2RayStatus
			if [[ "${installV2RayStatus}" == "y" ]]; then
				rm -f /etc/v2ray-agent/v2ray/v2ray
				rm -f /etc/v2ray-agent/v2ray/v2ctl
				updateV2Ray
			else
				echoContent green " ---> Give up update"
			fi

		fi
	fi
}

# 更新Xray
updateXray() {
	readInstallType
	if [[ -z "${coreInstallType}" ]]; then
		if [[ -n "$1" ]]; then
			version=$1
		else
			version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | jq -r .[0].tag_name)
		fi

		echoContent green " ---> Xray-core版本:${version}"

		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /etc/v2ray-agent/xray/ "https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip"
		else
			wget -c -P /etc/v2ray-agent/xray/ "https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip" >/dev/null 2>&1
		fi

		unzip -o /etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip -d /etc/v2ray-agent/xray >/dev/null
		rm -rf /etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip
		chmod 655 /etc/v2ray-agent/xray/xray
		handleXray stop
		handleXray start
	else
		echoContent green " ---> 当前Xray-core版本:$(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)"

		if [[ -n "$1" ]]; then
			version=$1
		else
			version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | jq -r .[0].tag_name)
		fi

		if [[ -n "$1" ]]; then
			read -r -p "The refund version is${version}，Whether to continue？[y/n]:" rollbackXrayStatus
			if [[ "${rollbackXrayStatus}" == "y" ]]; then
				echoContent green " ---> 当前Xray-core版本:$(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)"

				handleXray stop
				rm -f /etc/v2ray-agent/xray/xray
				updateXray "${version}"
			else
				echoContent green " ---> Give up the refund version"
			fi
		elif [[ "${version}" == "v$(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)" ]]; then
			read -r -p "The current version is the same as the latest version. Is it re -installed?[y/n]:" reInstallXrayStatus
			if [[ "${reInstallXrayStatus}" == "y" ]]; then
				handleXray stop
				rm -f /etc/v2ray-agent/xray/xray
				rm -f /etc/v2ray-agent/xray/xray
				updateXray
			else
				echoContent green " ---> Give up and reinstall"
			fi
		else
			read -r -p "The latest version is：${version}，Whether to update？[y/n]：" installXrayStatus
			if [[ "${installXrayStatus}" == "y" ]]; then
				rm -f /etc/v2ray-agent/xray/xray
				updateXray
			else
				echoContent green " ---> Give up update"
			fi

		fi
	fi
}
# 更新Trojan-Go
#updateTrojanGo() {
#	echoContent skyBlue "\n进度  $1/${totalProgress} : 更新Trojan-Go"
#	if [[ ! -d "/etc/v2ray-agent/trojan/" ]]; then
#		echoContent red " ---> 没有检测到安装目录，请执行脚本安装内容"
#		menu
#		exit 0
#	fi
#	if find /etc/v2ray-agent/trojan/ | grep -q "trojan-go"; then
#		version=$(curl -s https://api.github.com/repos/p4gefau1t/trojan-go/releases | jq -r .[0].tag_name)
#		echoContent green " ---> Trojan-Go版本:${version}"
#		if [[ -n $(wget --help | grep show-progress) ]]; then
#			wget -c -q --show-progress -P /etc/v2ray-agent/trojan/ "https://github.com/p4gefau1t/trojan-go/releases/download/${version}/${trojanGoCPUVendor}.zip"
#		else
#			wget -c -P /etc/v2ray-agent/trojan/ "https://github.com/p4gefau1t/trojan-go/releases/download/${version}/${trojanGoCPUVendor}.zip" >/dev/null 2>&1
#		fi
#		unzip -o /etc/v2ray-agent/trojan/${trojanGoCPUVendor}.zip -d /etc/v2ray-agent/trojan >/dev/null
#		rm -rf /etc/v2ray-agent/trojan/${trojanGoCPUVendor}.zip
#		handleTrojanGo stop
#		handleTrojanGo start
#	else
#		echoContent green " ---> 当前Trojan-Go版本:$(/etc/v2ray-agent/trojan/trojan-go --version | awk '{print $2}' | head -1)"
#		if [[ -n $(/etc/v2ray-agent/trojan/trojan-go --version) ]]; then
#			version=$(curl -s https://api.github.com/repos/p4gefau1t/trojan-go/releases | jq -r .[0].tag_name)
#			if [[ "${version}" == "$(/etc/v2ray-agent/trojan/trojan-go --version | awk '{print $2}' | head -1)" ]]; then
#				read -r -p "当前版本与最新版相同，是否重新安装？[y/n]:" reInstalTrojanGoStatus
#				if [[ "${reInstalTrojanGoStatus}" == "y" ]]; then
#					handleTrojanGo stop
#					rm -rf /etc/v2ray-agent/trojan/trojan-go
#					updateTrojanGo 1
#				else
#					echoContent green " ---> 放弃重新安装"
#				fi
#			else
#				read -r -p "最新版本为：${version}，是否更新？[y/n]：" installTrojanGoStatus
#				if [[ "${installTrojanGoStatus}" == "y" ]]; then
#					rm -rf /etc/v2ray-agent/trojan/trojan-go
#					updateTrojanGo 1
#				else
#					echoContent green " ---> 放弃更新"
#				fi
#			fi
#		fi
#	fi
#}

# 验证整个服务是否可用
checkGFWStatue() {
	readInstallType
	echoContent skyBlue "\n进度 $1/${totalProgress} : Verification service startup status"
	if [[ "${coreInstallType}" == "1" ]] && [[ -n $(pgrep -f xray/xray) ]]; then
		echoContent green " ---> The service starts successfully"
	elif [[ "${coreInstallType}" == "2" || "${coreInstallType}" == "3" ]] && [[ -n $(pgrep -f v2ray/v2ray) ]]; then
		echoContent green " ---> The service starts successfully"
	else
		echoContent red " ---> The service starts failed, please check if there is a log printing of the terminal"
		exit 0
	fi

}

# V2Ray开机自启
installV2RayService() {
	echoContent skyBlue "\nschedule  $1/${totalProgress} : Configure v2ray boot self -starting"
	if [[ -n $(find /bin /usr/bin -name "systemctl") ]]; then
		rm -rf /etc/systemd/system/v2ray.service
		touch /etc/systemd/system/v2ray.service
		execStart='/etc/v2ray-agent/v2ray/v2ray -confdir /etc/v2ray-agent/v2ray/conf'
		cat <<EOF >/etc/systemd/system/v2ray.service
[Unit]
Description=V2Ray - A unified platform for anti-censorship
Documentation=https://v2ray.com https://guide.v2fly.org
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=yes
ExecStart=${execStart}
Restart=on-failure
RestartPreventExitStatus=23


[Install]
WantedBy=multi-user.target
EOF
		systemctl daemon-reload
		systemctl enable v2ray.service
		echoContent green " ---> Configure V2RAY boot self -start success"
	fi
}

# Xray开机自启
installXrayService() {
	echoContent skyBlue "\nschedule  $1/${totalProgress} : Configure xRAY boot self -starting"
	if [[ -n $(find /bin /usr/bin -name "systemctl") ]]; then
		rm -rf /etc/systemd/system/xray.service
		touch /etc/systemd/system/xray.service
		execStart='/etc/v2ray-agent/xray/xray run -confdir /etc/v2ray-agent/xray/conf'
		cat <<EOF >/etc/systemd/system/xray.service
[Unit]
Description=Xray - A unified platform for anti-censorship
# Documentation=https://v2ray.com https://guide.v2fly.org
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=yes
ExecStart=${execStart}
Restart=on-failure
RestartPreventExitStatus=23


[Install]
WantedBy=multi-user.target
EOF
		systemctl daemon-reload
		systemctl enable xray.service
		echoContent green " ---> Configure xRAY boot self -start success"
	fi
}
# Trojan开机自启
installTrojanService() {
	echoContent skyBlue "\n进度  $1/${totalProgress} : Configure Trojan boot self -starting"
	if [[ -n $(find /bin /usr/bin -name "systemctl") ]]; then
		rm -rf /etc/systemd/system/trojan-go.service
		touch /etc/systemd/system/trojan-go.service

		cat <<EOF >/etc/systemd/system/trojan-go.service
[Unit]
Description=Trojan-Go - A unified platform for anti-censorship
Documentation=Trojan-Go
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=yes
ExecStart=/etc/v2ray-agent/trojan/trojan-go -config /etc/v2ray-agent/trojan/config_full.json
Restart=on-failure
RestartPreventExitStatus=23


[Install]
WantedBy=multi-user.target
EOF
		systemctl daemon-reload
		systemctl enable trojan-go.service
		echoContent green " ---> Configure TROJAN boot self -start success"
	fi
}
# 操作V2Ray
handleV2Ray() {
	# shellcheck disable=SC2010
	if find /bin /usr/bin | grep -q systemctl && ls /etc/systemd/system/ | grep -q v2ray.service; then
		if [[ -z $(pgrep -f "v2ray/v2ray") ]] && [[ "$1" == "start" ]]; then
			systemctl start v2ray.service
		elif [[ -n $(pgrep -f "v2ray/v2ray") ]] && [[ "$1" == "stop" ]]; then
			systemctl stop v2ray.service
		fi
	fi
	sleep 0.8

	if [[ "$1" == "start" ]]; then
		if [[ -n $(pgrep -f "v2ray/v2ray") ]]; then
			echoContent green " ---> V2ray successfully"
		else
			echoContent red "V2ray launch failure"
			echoContent red "Please manually execute [/etc/v2ray-agent/v2ray/v2ray -confdir/etc/v2ray-agent/v2ray/conf], check the error log"
			exit 0
		fi
	elif [[ "$1" == "stop" ]]; then
		if [[ -z $(pgrep -f "v2ray/v2ray") ]]; then
			echoContent green " ---> V2ray closed successfully"
		else
			echoContent red "V2Ray closed failure"
			echoContent red "Please execute manually【ps -ef|grep -v grep|grep v2ray|awk '{print \$2}'|xargs kill -9】"
			exit 0
		fi
	fi
}
# 操作xray
handleXray() {
	if [[ -n $(find /bin /usr/bin -name "systemctl") ]] && ls /etc/systemd/system/ | grep -q xray.service; then
		if [[ -z $(pgrep -f "xray/xray") ]] && [[ "$1" == "start" ]]; then
			systemctl start xray.service
		elif [[ -n $(pgrep -f "xray/xray") ]] && [[ "$1" == "stop" ]]; then
			systemctl stop xray.service
		fi
	fi

	sleep 0.8

	if [[ "$1" == "start" ]]; then
		if [[ -n $(pgrep -f "xray/xray") ]]; then
			echoContent green " ---> XRay successfully launched"
		else
			echoContent red "XRAY's launch failed"
			echoContent red "Please execute manually [/etc/v2ray-agent/xray/xray -confdir /etconf], view the error logt/xray/conf】，View error log"
			exit 0
		fi
	elif [[ "$1" == "stop" ]]; then
		if [[ -z $(pgrep -f "xray/xray") ]]; then
			echoContent green " ---> XRay closed successfully"
		else
			echoContent red "XRAY closed failure"
			echoContent red "Please execute manually【ps -ef|grep -v grep|grep xray|awk '{print \$2}'|xargs kill -9】"
			exit 0
		fi
	fi
}

# 操作Trojan-Go
handleTrojanGo() {
	if [[ -n $(find /bin /usr/bin -name "systemctl") ]] && ls /etc/systemd/system/ | grep -q trojan-go.service; then
		if [[ -z $(pgrep -f "trojan-go") ]] && [[ "$1" == "start" ]]; then
			systemctl start trojan-go.service
		elif [[ -n $(pgrep -f "trojan-go") ]] && [[ "$1" == "stop" ]]; then
			systemctl stop trojan-go.service
		fi
	fi

	sleep 0.5
	if [[ "$1" == "start" ]]; then
		if [[ -n $(pgrep -f "trojan-go") ]]; then
			echoContent green " ---> Trojan-Go successfully"
		else
			echoContent red "Trojan-Go启动失败"
			echoContent red "请手动执行【/etc/v2ray-agent/trojan/trojan-go -config /etc/v2ray-agent/trojan/config_full.json】，查看错误日志"
			exit 0
		fi
	elif [[ "$1" == "stop" ]]; then
		if [[ -z $(pgrep -f "trojan-go") ]]; then
			echoContent green " ---> Trojan-GO closed successfully"
		else
			echoContent red "Trojan-GO closed failure"
			echoContent red "请手动执行【ps -ef|grep -v grep|grep trojan-go|awk '{print \$2}'|xargs kill -9】"
			exit 0
		fi
	fi
}

# 初始化V2Ray 配置文件
initV2RayConfig() {
	echoContent skyBlue "\n进度 $2/${totalProgress} : Initialize V2Ray configuration"
	echo

	read -r -p "Whether to customize UUID ？[y/n]:" customUUIDStatus
	echo
	if [[ "${customUUIDStatus}" == "y" ]]; then
		read -r -p "Please enter the legal UUID:" currentCustomUUID
		if [[ -n "${currentCustomUUID}" ]]; then
			uuid=${currentCustomUUID}
		fi
	fi

	if [[ -n "${currentUUID}" && -z "${uuid}" ]]; then
		read -r -p "Read the previous installation record, whether to use the UUID at the time of the last installation ？[y/n]:" historyUUIDStatus
		if [[ "${historyUUIDStatus}" == "y" ]]; then
			uuid=${currentUUID}
		else
			uuid=$(/etc/v2ray-agent/v2ray/v2ctl uuid)
		fi
	elif [[ -z "${uuid}" ]]; then
		uuid=$(/etc/v2ray-agent/v2ray/v2ctl uuid)
	fi

	if [[ -z "${uuid}" ]]; then
		echoContent red "\n ---> UUID read error, re -generate"
		uuid=$(/etc/v2ray-agent/v2ray/v2ctl uuid)
	fi

	rm -rf /etc/v2ray-agent/v2ray/conf/*
	rm -rf /etc/v2ray-agent/v2ray/config_full.json

	cat <<EOF >/etc/v2ray-agent/v2ray/conf/00_log.json
{
  "log": {
    "error": "/etc/v2ray-agent/v2ray/error.log",
    "loglevel": "warning"
  }
}
EOF
	# outbounds
	if [[ -n "${pingIPv6}" ]]; then
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/10_ipv6_outbounds.json
{
    "outbounds": [
        {
          "protocol": "freedom",
          "settings": {},
          "tag": "direct"
        }
    ]
}
EOF
	else

		cat <<EOF >/etc/v2ray-agent/v2ray/conf/10_ipv4_outbounds.json
{
    "outbounds":[
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv4"
            },
            "tag":"IPv4-out"
        },
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv6"
            },
            "tag":"IPv6-out"
        },
        {
            "protocol":"blackhole",
            "tag":"blackhole-out"
        }
    ]
}
EOF
	fi


	# dns
	cat <<EOF >/etc/v2ray-agent/v2ray/conf/11_dns.json
{
    "dns": {
        "servers": [
          "localhost"
        ]
  }
}
EOF
	# VLESS_TCP_TLS/XTLS
	# 回落nginx
	local fallbacksList='{"dest":31300,"xver":0},{"alpn":"h2","dest":31302,"xver":0}'

#	if echo "${selectCustomInstallType}" | grep -q 4 || [[ "$1" == "all" ]]; then
#		# 回落trojan-go
#		fallbacksList='{"dest":31296,"xver":1},{"alpn":"h2","dest":31302,"xver":0}'
#	fi

if [[ -n $(echo "${selectCustomInstallType}" | grep 4) || "$1" == "all" ]]; then
#		fallbacksList=${fallbacksList}',{"path":"/'${customPath}'tcp","dest":31298,"xver":1}'
		fallbacksList='{"dest":31296,"xver":1},{"alpn":"h2","dest":31302,"xver":0}'
cat <<EOF >/etc/v2ray-agent/v2ray/conf/04_trojan_TCP_inbounds.json
{
"inbounds":[
	{
	  "port": 31296,
	  "listen": "127.0.0.1",
	  "protocol": "trojan",
	  "tag":"trojanTCP",
	  "settings": {
		"clients": [
		  {
			"password": "${uuid}",
			"email": "${domain}_trojan_tcp"
		  }
		],
		"fallbacks":[
			{"dest":"31300"}
		]
	  },
	  "streamSettings": {
		"network": "tcp",
		"security": "none",
		"tcpSettings": {
			"acceptProxyProtocol": true
		}
	  }
	}
	]
}
EOF
	fi

	# VLESS_WS_TLS
	if echo "${selectCustomInstallType}" | grep -q 1 || [[ "$1" == "all" ]]; then
		fallbacksList=${fallbacksList}',{"path":"/'${customPath}'ws","dest":31297,"xver":1}'
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/03_VLESS_WS_inbounds.json
{
"inbounds":[
    {
  "port": 31297,
  "listen": "127.0.0.1",
  "protocol": "vless",
  "tag":"VLESSWS",
  "settings": {
    "clients": [
      {
        "id": "${uuid}",
        "email": "${domain}_VLESS_WS"
      }
    ],
    "decryption": "none"
  },
  "streamSettings": {
    "network": "ws",
    "security": "none",
    "wsSettings": {
      "acceptProxyProtocol": true,
      "path": "/${customPath}ws"
    }
  }
}
]
}
EOF
	fi

	# VMess_TCP
#	if echo "${selectCustomInstallType}" | grep -q 2 || [[ "$1" == "all" ]]; then
#		fallbacksList=${fallbacksList}',{"path":"/'${customPath}'tcp","dest":31298,"xver":1}'
#		cat <<EOF >/etc/v2ray-agent/v2ray/conf/04_VMess_TCP_inbounds.json
#{
#"inbounds":[
#{
#  "port": 31298,
#  "listen": "127.0.0.1",
#  "protocol": "vmess",
#  "tag":"VMessTCP",
#  "settings": {
#    "clients": [
#      {
#        "id": "${uuid}",
#        "alterId": 0,
#        "email": "${domain}_vmess_tcp"
#      }
#    ]
#  },
#  "streamSettings": {
#    "network": "tcp",
#    "security": "none",
#    "tcpSettings": {
#      "acceptProxyProtocol": true,
#      "header": {
#        "type": "http",
#        "request": {
#          "path": [
#            "/${customPath}tcp"
#          ]
#        }
#      }
#    }
#  }
#}
#]
#}
#EOF
#	fi

	# VMess_WS
	if echo "${selectCustomInstallType}" | grep -q 3 || [[ "$1" == "all" ]]; then
		fallbacksList=${fallbacksList}',{"path":"/'${customPath}'vws","dest":31299,"xver":1}'
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/05_VMess_WS_inbounds.json
{
"inbounds":[
{
  "port": 31299,
  "protocol": "vmess",
  "tag":"VMessWS",
  "settings": {
    "clients": [
      {
        "id": "${uuid}",
        "alterId": 0,
        "add": "${add}",
        "email": "${domain}_vmess_ws"
      }
    ]
  },
  "streamSettings": {
    "network": "ws",
    "security": "none",
    "wsSettings": {
      "acceptProxyProtocol": true,
      "path": "/${customPath}vws"
    }
  }
}
]
}
EOF
	fi
	# VLESS gRPC
	if echo "${selectCustomInstallType}" | grep -q 5 || [[ "$1" == "all" ]]; then
#		fallbacksList=${fallbacksList}',{"alpn":"h2","dest":31301,"xver":0}'
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/06_VLESS_gRPC_inbounds.json
{
    "inbounds":[
    {
        "port": 31301,
        "listen": "127.0.0.1",
        "protocol": "vless",
        "tag":"VLESSGRPC",
        "settings": {
            "clients": [
                {
                    "id": "${uuid}",
                    "add": "${add}",
        			"email": "${domain}_VLESS_gRPC"
                }
            ],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "grpc",
            "grpcSettings": {
                "serviceName": "${customPath}grpc"
            }
        }
    }
]
}
EOF
	fi

	# VLESS_TCP
	if [[ "${selectCoreType}" == "2" ]]; then
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json
{
  "inbounds":[
    {
      "port": 443,
      "protocol": "vless",
      "tag":"VLESSTCP",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "add": "${add}",
            "email": "${domain}_VLESS_TLS_TCP"
          }
        ],
        "decryption": "none",
        "fallbacks": [
        	${fallbacksList}
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "alpn": [
            "http/1.1",
            "h2"
          ],
          "certificates": [
            {
              "certificateFile": "/etc/v2ray-agent/tls/${domain}.crt",
              "keyFile": "/etc/v2ray-agent/tls/${domain}.key"
            }
          ]
        }
      }
    }
  ]
}
EOF
	elif [[ "${selectCoreType}" == "3" ]]; then
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json
{
"inbounds":[
{
  "port": 443,
  "protocol": "vless",
  "tag":"VLESSTCP",
  "settings": {
    "clients": [
     {
        "id": "${uuid}",
        "add":"${add}",
        "flow":"xtls-rprx-direct",
        "email": "${domain}_VLESS_XTLS/TLS-direct_TCP"
      }
    ],
    "decryption": "none",
    "fallbacks": [
        ${fallbacksList}
    ]
  },
  "streamSettings": {
    "network": "tcp",
    "security": "xtls",
    "xtlsSettings": {
      "alpn": [
        "http/1.1"
      ],
      "certificates": [
        {
          "certificateFile": "/etc/v2ray-agent/tls/${domain}.crt",
          "keyFile": "/etc/v2ray-agent/tls/${domain}.key"
        }
      ]
    }
  }
}
]
}
EOF
	fi
#
#	if echo "${selectCustomInstallType}" | grep -q 5 || [[ "$1" == "all" ]];then
#		echo >/dev/null
#	elif [[ -f "/etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json" ]] && echo "${selectCustomInstallType}" | grep -q 4;then
#		# "h2",
#		sed -i '/\"h2\",/d' $(grep "\"h2\"," -rl /etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json)
#	fi
}

# 初始化Xray Trojan XTLS 配置文件
initXrayFrontingConfig(){
	if [[ -z "${configPath}" ]]; then
		echoContent red " ---> Not installed, please use scripts to install"
		menu
		exit 0
	fi
	if [[ "${coreInstallType}" != "1" ]];then
		echoContent red " ---> Unpacking type"
	fi
	local xtlsType=
	if echo ${currentInstallProtocolType} | grep -q trojan; then
		xtlsType=VLESS
	else
		xtlsType=Trojan

	fi

	echoContent skyBlue "\n功能 1/${totalProgress} : Front switch to${xtlsType}"
	echoContent red "\n=============================================================="
	echoContent yellow "# Precautions\n"
	echoContent yellow "Will replace the front to${xtlsType}"
	echoContent yellow "If the front is Trojan, when you check the account, there will be two Trojan protocol nodes."
	echoContent yellow "Execute again to switch to the previous front\n"

	echoContent yellow "1.Switch to${xtlsType}"
	echoContent red "=============================================================="
	read -r -p "please choose:" selectType
	if [[ "${selectType}" == "1" ]]; then

		if [[ "${xtlsType}" == "Trojan" ]];then

			local VLESSConfig=$(cat ${configPath}${frontingType}.json)
			VLESSConfig=${VLESSConfig//"id"/"password"}
			VLESSConfig=${VLESSConfig//VLESSTCP/TrojanTCPXTLS}
			VLESSConfig=${VLESSConfig//VLESS/Trojan}
			VLESSConfig=${VLESSConfig//"vless"/"trojan"}
			VLESSConfig=${VLESSConfig//"id"/"password"}

			echo "${VLESSConfig}" | jq . >${configPath}02_trojan_TCP_inbounds.json
			rm  ${configPath}${frontingType}.json
		elif [[ "${xtlsType}" == "VLESS" ]]; then

			local VLESSConfig=$(cat ${configPath}02_trojan_TCP_inbounds.json)
			VLESSConfig=${VLESSConfig//"password"/"id"}
			VLESSConfig=${VLESSConfig//TrojanTCPXTLS/VLESSTCP}
			VLESSConfig=${VLESSConfig//Trojan/VLESS}
			VLESSConfig=${VLESSConfig//"trojan"/"vless"}
			VLESSConfig=${VLESSConfig//"password"/"id"}

			echo "${VLESSConfig}" | jq . >${configPath}02_VLESS_TCP_inbounds.json
			rm ${configPath}02_trojan_TCP_inbounds.json
		fi
		reloadCore
	fi

	exit 0;
}

# 初始化Xray 配置文件
initXrayConfig() {
	echoContent skyBlue "\n进度 $2/${totalProgress} : Initialize XRAY configuration"
	echo
	local uuid=
	if [[ -n "${currentUUID}" ]]; then
		read -r -p "Read the previous installation record, whether to use the UUID at the time of the last installation ？[y/n]:" historyUUIDStatus
		if [[ "${historyUUIDStatus}" == "y" ]]; then
			uuid=${currentUUID}
			echoContent green "\n ---> Successful use"
		else
			uuid=$(/etc/v2ray-agent/xray/xray uuid)
		fi
	fi

	if [[ -z "${uuid}" ]];then
		echoContent yellow "Please enter the custom UUID[Need to be legal], [Enter] RandomUUID"
		read -r -p 'UUID:' customUUID

		if [[ -n ${customUUID} ]];then
			uuid=${customUUID}
		else
			uuid=$(/etc/v2ray-agent/xray/xray uuid)
		fi

	fi

	if [[ -z "${uuid}" ]]; then
		echoContent red "\n ---> UUID read error, re -generate"
		uuid=$(/etc/v2ray-agent/xray/xray uuid)
	fi

	echoContent yellow "\n ${uuid}"

	rm -rf /etc/v2ray-agent/xray/conf/*

	# log
	cat <<EOF >/etc/v2ray-agent/xray/conf/00_log.json
{
  "log": {
    "error": "/etc/v2ray-agent/xray/error.log",
    "loglevel": "warning"
  }
}
EOF

	# outbounds
	if [[ -n "${pingIPv6}" ]]; then
		cat <<EOF >/etc/v2ray-agent/xray/conf/10_ipv6_outbounds.json
{
    "outbounds": [
        {
          "protocol": "freedom",
          "settings": {},
          "tag": "direct"
        }
    ]
}
EOF

	else
		cat <<EOF >/etc/v2ray-agent/xray/conf/10_ipv4_outbounds.json
{
    "outbounds":[
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv4"
            },
            "tag":"IPv4-out"
        },
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv6"
            },
            "tag":"IPv6-out"
        },
        {
            "protocol":"blackhole",
            "tag":"blackhole-out"
        }
    ]
}
EOF
	fi


	# dns
	cat <<EOF >/etc/v2ray-agent/xray/conf/11_dns.json
{
    "dns": {
        "servers": [
          "localhost"
        ]
  }
}
EOF

	# VLESS_TCP_TLS/XTLS
	# 回落nginx
	local fallbacksList='{"dest":31300,"xver":0},{"alpn":"h2","dest":31302,"xver":0}'

	# trojan
	if [[ -n $(echo "${selectCustomInstallType}" | grep 4) || "$1" == "all" ]]; then
		fallbacksList='{"dest":31296,"xver":1},{"alpn":"h2","dest":31302,"xver":0}'
		cat <<EOF >/etc/v2ray-agent/xray/conf/04_trojan_TCP_inbounds.json
{
"inbounds":[
	{
	  "port": 31296,
	  "listen": "127.0.0.1",
	  "protocol": "trojan",
	  "tag":"trojanTCP",
	  "settings": {
		"clients": [
		  {
			"password": "${uuid}",
			"email": "${domain}_trojan_tcp"
		  }
		],
		"fallbacks":[
			{"dest":"31300"}
		]
	  },
	  "streamSettings": {
		"network": "tcp",
		"security": "none",
		"tcpSettings": {
			"acceptProxyProtocol": true
		}
	  }
	}
	]
}
EOF
	fi

	# VLESS_WS_TLS
	if echo "${selectCustomInstallType}" | grep -q 1 || [[ "$1" == "all" ]]; then
		fallbacksList=${fallbacksList}',{"path":"/'${customPath}'ws","dest":31297,"xver":1}'
		cat <<EOF >/etc/v2ray-agent/xray/conf/03_VLESS_WS_inbounds.json
{
"inbounds":[
    {
  "port": 31297,
  "listen": "127.0.0.1",
  "protocol": "vless",
  "tag":"VLESSWS",
  "settings": {
    "clients": [
      {
        "id": "${uuid}",
        "email": "${domain}_VLESS_WS"
      }
    ],
    "decryption": "none"
  },
  "streamSettings": {
    "network": "ws",
    "security": "none",
    "wsSettings": {
      "acceptProxyProtocol": true,
      "path": "/${customPath}ws"
    }
  }
}
]
}
EOF
	fi


	# trojan_grpc
	if echo ${selectCustomInstallType} | grep -q 2 || [[ "$1" == "all" ]]; then
		if ! echo ${selectCustomInstallType} | grep -q 5 && [[ -n ${selectCustomInstallType} ]];then
			fallbacksList=${fallbacksList//31302/31304}
		fi

		cat <<EOF >/etc/v2ray-agent/xray/conf/04_trojan_gRPC_inbounds.json
{
    "inbounds": [
        {
            "port": 31304,
            "listen": "127.0.0.1",
            "protocol": "trojan",
            "tag": "trojangRPCTCP",
            "settings": {
                "clients": [
                    {
                        "password": "${uuid}",
                        "email": "${domain}_trojan_gRPC"
                    }
                ],
                "fallbacks": [
                    {
                        "dest": "31300"
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "${customPath}trojangrpc"
                }
            }
        }
    ]
}
EOF
	fi


	# VMess_WS
	if echo "${selectCustomInstallType}" | grep -q 3 || [[ "$1" == "all" ]]; then
		fallbacksList=${fallbacksList}',{"path":"/'${customPath}'vws","dest":31299,"xver":1}'
		cat <<EOF >/etc/v2ray-agent/xray/conf/05_VMess_WS_inbounds.json
{
"inbounds":[
{
  "port": 31299,
  "protocol": "vmess",
  "tag":"VMessWS",
  "settings": {
    "clients": [
      {
        "id": "${uuid}",
        "alterId": 0,
        "add": "${add}",
        "email": "${domain}_vmess_ws"
      }
    ]
  },
  "streamSettings": {
    "network": "ws",
    "security": "none",
    "wsSettings": {
      "acceptProxyProtocol": true,
      "path": "/${customPath}vws"
    }
  }
}
]
}
EOF
	fi

	if echo "${selectCustomInstallType}" | grep -q 5 || [[ "$1" == "all" ]]; then
#		fallbacksList=${fallbacksList}',{"alpn":"h2","dest":31302,"xver":0}'
		cat <<EOF >/etc/v2ray-agent/xray/conf/06_VLESS_gRPC_inbounds.json
{
    "inbounds":[
    {
        "port": 31301,
        "listen": "127.0.0.1",
        "protocol": "vless",
        "tag":"VLESSGRPC",
        "settings": {
            "clients": [
                {
                    "id": "${uuid}",
                    "add": "${add}",
                    "email": "${domain}_VLESS_gRPC"
                }
            ],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "grpc",
            "grpcSettings": {
                "serviceName": "${customPath}grpc"
            }
        }
    }
]
}
EOF
	fi

	# VLESS_TCP
	cat <<EOF >/etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json
{
"inbounds":[
{
  "port": 443,
  "protocol": "vless",
  "tag":"VLESSTCP",
  "settings": {
    "clients": [
     {
        "id": "${uuid}",
        "add":"${add}",
        "flow":"xtls-rprx-direct",
        "email": "${domain}_VLESS_XTLS/TLS-direct_TCP"
      }
    ],
    "decryption": "none",
    "fallbacks": [
        ${fallbacksList}
    ]
  },
  "streamSettings": {
    "network": "tcp",
    "security": "xtls",
    "xtlsSettings": {
      "minVersion": "1.2",
      "alpn": [
        "http/1.1",
        "h2"
      ],
      "certificates": [
        {
          "certificateFile": "/etc/v2ray-agent/tls/${domain}.crt",
          "keyFile": "/etc/v2ray-agent/tls/${domain}.key",
          "ocspStapling": 3600,
          "usage":"encipherment"
        }
      ]
    }
  }
}
]
}
EOF
#	if echo "${selectCustomInstallType}" | grep -q 5 || [[ "$1" == "all" ]];then
#		echo >/dev/null
#	elif [[ -f "/etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json" ]] && echo "${selectCustomInstallType}" | grep -q 4;then
#		# "h2",
#		sed -i '/\"h2\",/d' $(grep "\"h2\"," -rl /etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json)
#	fi
}

# 初始化Trojan-Go配置
initTrojanGoConfig() {

	echoContent skyBlue "\n进度 $1/${totalProgress} : 初始化Trojan配置"
	cat <<EOF >/etc/v2ray-agent/trojan/config_full.json
{
    "run_type": "server",
    "local_addr": "127.0.0.1",
    "local_port": 31296,
    "remote_addr": "127.0.0.1",
    "remote_port": 31300,
    "disable_http_check":true,
    "log_level":3,
    "log_file":"/etc/v2ray-agent/trojan/trojan.log",
    "password": [
        "${uuid}"
    ],
    "dns":[
        "localhost"
    ],
    "transport_plugin":{
        "enabled":true,
        "type":"plaintext"
    },
    "websocket": {
        "enabled": true,
        "path": "/${customPath}tws",
        "host": "${domain}",
        "add":"${add}"
    },
    "router": {
        "enabled": false
    }
}
EOF
}

# 自定义CDN IP
customCDNIP() {
	echoContent skyBlue "\n进度 $1/${totalProgress} : Add DNS intelligent analysis"
	echoContent yellow "\n, if you do n’t know about the IP of the cloudflare, please select[n]"
	echoContent yellow "\n move:104.16.123.96"
	echoContent yellow " Connect:hostmonit.com"
	echoContent yellow " telecommunications:www.digitalocean.com"
	echoContent skyBlue "----------------------------"
	read -r -p '是否使用？[y/n]:' dnsProxy
	if [[ "${dnsProxy}" == "y" ]]; then
		add="domain08.mqcjuc.ml"
		echoContent green "\n ---> 使用成功"
	else
		add="${domain}"
	fi
}

# 通用
defaultBase64Code() {
	local type=$1
	local email=$2
	local id=$3
	local hostPort=$4
	local host=
	local port=
	if echo "${hostPort}" | grep -q ":"; then
		host=$(echo "${hostPort}" | awk -F "[:]" '{print $1}')
		port=$(echo "${hostPort}" | awk -F "[:]" '{print $2}')
	else
		host=${hostPort}
		port=443
	fi

	local path=$5
	local add=$6

	local subAccount=${currentHost}_$(echo "${id}_currentHost" | md5sum | awk '{print $1}')
	if [[ "${type}" == "vlesstcp" ]]; then

		if [[ "${coreInstallType}" == "1" ]] && echo ${currentInstallProtocolType} | grep -q 0; then
			echoContent yellow " ---> Universal format(VLESS+TCP+TLS/xtls-rprx-direct)"
			echoContent green "    vless://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-direct#${email}\n"

			echoContent yellow " ---> Format(VLESS+TCP+TLS/xtls-rprx-direct)"
			echoContent green "协议类型：VLESS，地址：${host}，端口：${port}，用户ID：${id}，安全：xtls，传输方式：tcp，flow：xtls-rprx-direct，账户名:${email}\n"
			cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-direct#${email}
EOF
			echoContent yellow " ---> 二维码 VLESS(VLESS+TCP+TLS/xtls-rprx-direct)"
			echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${host}%3A${port}%3F${encryption}%3Dnone%26security%3Dxtls%26type%3Dtcp%26${host}%3D${host}%26headerType%3Dnone%26sni%3D${host}%26flow%3Dxtls-rprx-direct%23${email}\n"

			echoContent skyBlue "----------------------------------------------------------------------------------"

			echoContent yellow " ---> 通用格式(VLESS+TCP+TLS/xtls-rprx-splice)"
			echoContent green "    vless://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-splice#${email}\n"

			echoContent yellow " ---> 格式化明文(VLESS+TCP+TLS/xtls-rprx-splice)"
			echoContent green "    协议类型：VLESS，地址：${host}，端口：${port}，用户ID：${id}，安全：xtls，传输方式：tcp，flow：xtls-rprx-splice，账户名:${email}\n"
			cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-splice#${email}
EOF
			echoContent yellow " ---> 二维码 VLESS(VLESS+TCP+TLS/xtls-rprx-splice)"
			echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${host}%3A${port}%3F${encryption}%3Dnone%26security%3Dxtls%26type%3Dtcp%26${host}%3D${host}%26headerType%3Dnone%26sni%3D${host}%26flow%3Dxtls-rprx-splice%23${email}\n"

		elif [[ "${coreInstallType}" == "2" || "${coreInstallType}" == "3" ]]; then
			echoContent yellow " ---> 通用格式(VLESS+TCP+TLS)"
			echoContent green "    vless://${id}@${host}:${port}?security=tls&encryption=none&host=${host}&headerType=none&type=tcp#${email}\n"

			echoContent yellow " ---> 格式化明文(VLESS+TCP+TLS/xtls-rprx-splice)"
			echoContent green "    协议类型：VLESS，地址：${host}，端口：${port}，用户ID：${id}，安全：tls，传输方式：tcp，账户名:${email}\n"

			cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${host}:${port}?security=tls&encryption=none&host=${host}&headerType=none&type=tcp#${email}
EOF
			echoContent yellow " ---> 二维码 VLESS(VLESS+TCP+TLS)"
			echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3a%2f%2f${id}%40${host}%3a${port}%3fsecurity%3dtls%26encryption%3dnone%26host%3d${host}%26headerType%3dnone%26type%3dtcp%23${email}\n"
		fi

	elif [[ "${type}" == "trojanTCPXTLS" ]]; then
			echoContent yellow " ---> 通用格式(Trojan+TCP+TLS/xtls-rprx-direct)"
			echoContent green "    trojan://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-direct#${email}\n"

			echoContent yellow " ---> 格式化明文(Trojan+TCP+TLS/xtls-rprx-direct)"
			echoContent green "协议类型：Trojan，地址：${host}，端口：${port}，用户ID：${id}，安全：xtls，传输方式：tcp，flow：xtls-rprx-direct，账户名:${email}\n"
			cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-direct#${email}
EOF
			echoContent yellow " ---> 二维码 Trojan(Trojan+TCP+TLS/xtls-rprx-direct)"
			echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3A%2F%2F${id}%40${host}%3A${port}%3Fencryption%3Dnone%26security%3Dxtls%26type%3Dtcp%26${host}%3D${host}%26headerType%3Dnone%26sni%3D${host}%26flow%3Dxtls-rprx-direct%23${email}\n"

			echoContent skyBlue "----------------------------------------------------------------------------------"

			echoContent yellow " ---> 通用格式(Trojan+TCP+TLS/xtls-rprx-splice)"
			echoContent green "    trojan://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-splice#${email}\n"

			echoContent yellow " ---> 格式化明文(Trojan+TCP+TLS/xtls-rprx-splice)"
			echoContent green "    协议类型：VLESS，地址：${host}，端口：${port}，用户ID：${id}，安全：xtls，传输方式：tcp，flow：xtls-rprx-splice，账户名:${email}\n"
			cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-splice#${email}
EOF
			echoContent yellow " ---> 二维码 Trojan(Trojan+TCP+TLS/xtls-rprx-splice)"
			echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3A%2F%2F${id}%40${host}%3A${port}%3Fencryption%3Dnone%26security%3Dxtls%26type%3Dtcp%26${host}%3D${host}%26headerType%3Dnone%26sni%3D${host}%26flow%3Dxtls-rprx-splice%23${email}\n"


	elif [[ "${type}" == "vmessws" ]]; then

		qrCodeBase64Default=$(echo -n '{"port":"'${port}'","ps":'\"${email}\"',"tls":"tls","id":'\"${id}\"',"aid":"0","v":"2","host":"'${host}'","type":"none","path":"/'${path}'","net":"ws","add":"'${add}'","allowInsecure":0,"method":"none","peer":"'${host}'","sni":"'${host}'"}' | sed 's#/#\\\/#g' | base64)
		qrCodeBase64Default=$(echo ${qrCodeBase64Default} | sed 's/ //g')

		echoContent yellow " ---> 通用json(VMess+WS+TLS)"
		echoContent green '    {"port":"'${port}'","ps":'\"${ps}\"',"tls":"tls","id":'\"${id}\"',"aid":"0","v":"2","host":"'${host}'","type":"none","path":"/'${path}'","net":"ws","add":"'${add}'","allowInsecure":0,"method":"none","peer":"'${host}'","sni":"'${host}'"}\n'
		echoContent yellow " ---> 通用vmess(VMess+WS+TLS)链接"
		echoContent green "    vmess://${qrCodeBase64Default}\n"
		echoContent yellow " ---> 二维码 vmess(VMess+WS+TLS)"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vmess://${qrCodeBase64Default}
EOF
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vmess://${qrCodeBase64Default}\n"

	elif [[ "${type}" == "vmesstcp" ]]; then

#		echoContent yellow " ---> 通用格式[新版，推荐]"
#
#		echoContent green "    vmess://tcp+tls:2e6257c5-1402-41a6-a96d-1e0bdad78159-0@vu3.s83h.xyz:443/?type=http&tlsServerName=vu3.s83h.xyz#vu3.s83h.xyz_vmess_tcp"
#		echoContent green "    vmess://tcp+tls:${id//\"/}-0@${add}:${port}/?type=http&path=/${path}&tlsServerName=${host}&alpn=http1.1#${ps//\"/}\n"
#
#		echoContent yellow " ---> 格式化明文(vmess+http+tls)"
#		echoContent green "协议类型：vmess，地址：${host}，端口：${port}，用户ID：${id}，安全：tls，传输方式：http，账户名:${ps}\n"
#		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
#vmess://http+tls:${id}-0@${add}:${port}/?path=/${path}&tlsServerName=${host}&alpn=http1.1#${ps}
#EOF
#		echoContent yellow " ---> 二维码 vmess(http+tls)"
#		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vmess%3A%2F%2Fhttp%2Btls%3A${id}-0%40add%3A${port}%2F%3Fpath%3D%2F${path}%26tlsServerName%3D${host}%26alpn%3Dhttp1.1%23%24%7B${ps}%7D\n"

		echoContent red path:${path}
		qrCodeBase64Default=$(echo -n '{"add":"'${add}'","aid":"0","host":"'${host}'","id":'"${id}"',"net":"tcp","path":"/'${path}'","port":"'${port}'","ps":'${ps}',"scy":"none","sni":"'${host}'","tls":"tls","v":"2","type":"http","allowInsecure":0,"peer":"'${host}'","obfs":"http","obfsParam":"'${host}'"}'  | base64)
		qrCodeBase64Default=$(echo ${qrCodeBase64Default} | sed 's/ //g')

		echoContent yellow " ---> GM JSON(VMess+TCP+TLS)"
		echoContent green '    {"port":"'${port}'","ps":'${ps}',"tls":"tls","id":'"${id}"',"aid":"0","v":"2","host":"'${host}'","type":"http","path":"/'${path}'","net":"http","add":"'${add}'","allowInsecure":0,"method":"post","peer":"'${host}'","obfs":"http","obfsParam":"'${host}'"}\n'
		echoContent yellow " ---> GM VMESS(VMess+TCP+TLS)链接"
		echoContent green "    vmess://${qrCodeBase64Default}\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vmess://${qrCodeBase64Default}
EOF
		echoContent yellow " ---> QR code vmess(VMess+TCP+TLS)"
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vmess://${qrCodeBase64Default}\n"

	elif [[ "${type}" == "vlessws" ]]; then

		echoContent yellow " ---> Universal format(VLESS+WS+TLS)"
		echoContent green "    vless://${id}@${add}:${port}?encryption=none&security=tls&type=ws&host=${host}&sni=${host}&path=%2f${path}#${email}\n"

		echoContent yellow " ---> Format(VLESS+WS+TLS)"
		echoContent green "    协议类型：VLESS，地址：${add}，伪装域名/SNI：${host}，端口：${port}，用户ID：${id}，安全：tls，传输方式：ws，路径:/${path}，账户名:${email}\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${add}:${port}?encryption=none&security=tls&type=ws&host=${host}&sni=${host}&path=%2f${path}#${email}
EOF

		echoContent yellow " ---> 二维码 VLESS(VLESS+TCP+TLS/XTLS)"
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${add}%3A${port}%3Fencryption%3Dnone%26security%3Dtls%26type%3Dws%26host%3D${host}%26sni%3D${host}%26path%3D%252f${path}%23${email}"

	elif [[ "${type}" == "vlessgrpc" ]]; then

		echoContent yellow " ---> Universal format(VLESS+gRPC+TLS)"
		echoContent green "    vless://${id}@${add}:${port}?encryption=none&security=tls&type=grpc&host=${host}&path=${path}&serviceName=${path}&alpn=h2&sni=${host}#${email}\n"

		echoContent yellow " ---> Format(VLESS+gRPC+TLS)"
		echoContent green "    协议类型：VLESS，地址：${add}，伪装域名/SNI：${host}，端口：${port}，用户ID：${id}，安全：tls，传输方式：gRPC，alpn：h2，serviceName:${path}，账户名:${email}\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${add}:${port}?encryption=none&security=tls&type=grpc&host=${host}&path=${path}&serviceName=${path}&alpn=h2&sni=${host}#${email}
EOF
		echoContent yellow " ---> 二维码 VLESS(VLESS+gRPC+TLS)"
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${add}%3A${port}%3Fencryption%3Dnone%26security%3Dtls%26type%3Dgrpc%26host%3D${host}%26serviceName%3D${path}%26path%3D${path}%26sni%3D${host}%26alpn%3Dh2%23${email}"

	elif [[ "${type}" == "trojan" ]]; then
		# URLEncode
		echoContent yellow " ---> Trojan(TLS)"
		echoContent green "    trojan://${id}@${host}:${port}?peer=${host}&sni=${host}&alpn=http1.1#${host}_Trojan\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${host}:${port}?peer=${host}&sni=${host}&alpn=http1.1#${host}_Trojan
EOF
		echoContent yellow " ---> 二维码 Trojan(TLS)"
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3a%2f%2f${id}%40${host}%3a${port}%3fpeer%3d${host}%26sni%3d${host}%26alpn%3Dhttp1.1%23${host}_Trojan\n"

	elif [[ "${type}" == "trojangrpc" ]]; then
		# URLEncode

		echoContent yellow " ---> Trojan gRPC(TLS)"
		echoContent green "    trojan://${id}@${host}:${port}?encryption=none&peer=${host}&security=tls&type=grpc&sni=${host}&alpn=h2&path=${path}&serviceName=${path}#${host}_Trojan_gRPC\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${host}:${port}?encryption=none&peer=${host}&security=tls&type=grpc&sni=${host}&alpn=h2&path=${path}&serviceName=${path}#${host}_Trojan_gRPC
EOF
		echoContent yellow " ---> 二维码 Trojan gRPC(TLS)"
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3a%2f%2f${id}%40${host}%3a${port}%3Fencryption%3Dnone%26security%3Dtls%26peer%3d${host}%26type%3Dgrpc%26sni%3d${host}%26path%3D${path}%26alpn%3D=h2%26serviceName%3D${path}%23${host}_Trojan_gRPC\n"

	elif [[ "${type}" == "trojangows" ]]; then
		# URLEncode
		echoContent yellow " ---> Trojan-Go(WS+TLS) Shadowrocket"
		echoContent green "    trojan://${id}@${add}:${port}?allowInsecure=0&&peer=${host}&sni=${host}&plugin=obfs-local;obfs=websocket;obfs-host=${host};obfs-uri=${path}#${host}_Trojan_ws\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${add}:${port}?allowInsecure=0&&peer=${host}&sni=${host}&plugin=obfs-local;obfs=websocket;obfs-host=${host};obfs-uri=${path}#${host}_Trojan_ws
EOF
		echoContent yellow " ---> 二维码 Trojan-Go(WS+TLS) Shadowrocket"
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3a%2f%2f${id}%40${add}%3a${port}%3fallowInsecure%3d0%26peer%3d${host}%26plugin%3dobfs-local%3bobfs%3dwebsocket%3bobfs-host%3d${host}%3bobfs-uri%3d${path}%23${host}_Trojan_ws\n"

		path=$(echo "${path}" | awk -F "[/]" '{print $2}')
		echoContent yellow " ---> Trojan-Go(WS+TLS) QV2ray"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan-go://${id}@${add}:${port}?sni=${host}&type=ws&host=${host}&path=%2F${path}#${host}_Trojan_ws
EOF

		echoContent green "    trojan-go://${id}@${add}:${port}?sni=${host}&type=ws&host=${host}&path=%2F${path}#${host}_Trojan_ws\n"

	fi
}
# 账号
showAccounts() {
	readInstallType
	readInstallProtocolType
	readConfigHostPathUUID
	echoContent skyBlue "\n进度 $1/${totalProgress} : 账号"
	local show
	# VLESS TCP
	if [[ -n "${configPath}" ]]; then
		show=1
		if  echo "${currentInstallProtocolType}" | grep -q trojan ;then
			echoContent skyBlue "===================== Trojan TCP TLS/XTLS-direct/XTLS-splice ======================\n"
			# cat ${configPath}02_VLESS_TCP_inbounds.json | jq .inbounds[0].settings.clients | jq -c '.[]'
			jq .inbounds[0].settings.clients ${configPath}02_trojan_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
				echoContent skyBlue "\n ---> 帐号：$(echo "${user}" | jq -r .email )_$(echo "${user}" | jq -r .password)"
				echo
				defaultBase64Code trojanTCPXTLS $(echo "${user}" | jq -r .email) $(echo "${user}" | jq -r .password) "${currentHost}:${currentPort}" ${currentHost}
			done

		else
			echoContent skyBlue "===================== VLESS TCP TLS/XTLS-direct/XTLS-splice ======================\n"
			# cat ${configPath}02_VLESS_TCP_inbounds.json | jq .inbounds[0].settings.clients | jq -c '.[]'
			jq .inbounds[0].settings.clients ${configPath}02_VLESS_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
				echoContent skyBlue "\n ---> 帐号：$(echo "${user}" | jq -r .email )_$(echo "${user}" | jq -r .id)"
				echo
				defaultBase64Code vlesstcp $(echo "${user}" | jq -r .email) $(echo "${user}" | jq -r .id) "${currentHost}:${currentPort}" ${currentHost}
			done
		fi


		# VLESS WS
		if echo ${currentInstallProtocolType} | grep -q 1; then
			echoContent skyBlue "\n================================ VLESS WS TLS CDN ================================\n"

			# cat ${configPath}03_VLESS_WS_inbounds.json | jq .inbounds[0].settings.clients | jq -c '.[]'
			jq .inbounds[0].settings.clients ${configPath}03_VLESS_WS_inbounds.json | jq -c '.[]' | while read -r user; do
				echoContent skyBlue "\n ---> 帐号：$(echo "${user}" | jq -r .email )_$(echo "${user}" | jq -r .id)"
				echo
				local path="${currentPath}ws"
				if [[ ${coreInstallType} == "1" ]]; then
					echoContent yellow "Xray的0-RTT path后面会有?ed=2048，不兼容以v2ray为核心的客户端，请手动删除?ed=2048后使用\n"
					path="${currentPath}ws?ed=2048"
				fi
				defaultBase64Code vlessws $(echo "${user}" | jq -r .email) $(echo "${user}" | jq -r .id) "${currentHost}:${currentPort}" ${path} ${currentAdd}
			done
		fi

		# VMess TCP
#		if echo ${currentInstallProtocolType} | grep -q 2; then
#			echoContent skyBlue "\n================================= VMess TCP TLS  =================================\n"
#
#			# cat ${configPath}04_VMess_TCP_inbounds.json | jq .inbounds[0].settings.clients | jq -c '.[]'
#			jq .inbounds[0].settings.clients ${configPath}04_VMess_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
#				echoContent skyBlue "\n ---> 帐号：$(echo "${user}" | jq -r .email )_$(echo "${user}" | jq -r .id)"
#				echo
#				defaultBase64Code vmesstcp $(echo "${user}" | jq .email) $(echo "${user}" | jq .id) "${currentHost}:${currentPort}" "${currentPath}tcp" "${currentHost}"
#			done
#		fi

		# VMess WS
		if echo ${currentInstallProtocolType} | grep -q 3; then
			echoContent skyBlue "\n================================ VMess WS TLS CDN ================================\n"
			local path="${currentPath}vws"
			if [[ ${coreInstallType} == "1" ]]; then
				path="${currentPath}vws?ed=2048"
			fi
			jq .inbounds[0].settings.clients ${configPath}05_VMess_WS_inbounds.json | jq -c '.[]' | while read -r user; do
				echoContent skyBlue "\n ---> 帐号：$(echo "${user}" | jq -r .email )_$(echo "${user}" | jq -r .id)"
				echo
				defaultBase64Code vmessws $(echo "${user}" | jq -r .email) $(echo "${user}" | jq -r .id) "${currentHost}:${currentPort}" ${path} ${currentAdd}
			done
		fi

		# VLESS grpc
		if echo ${currentInstallProtocolType} | grep -q 5; then
			echoContent skyBlue "\n=============================== VLESS gRPC TLS CDN ===============================\n"
			echoContent red "\n --->gRPC目前处于测试阶段，可能对你使用的客户端不兼容，如不能使用请忽略"
			local serviceName=$(jq -r .inbounds[0].streamSettings.grpcSettings.serviceName ${configPath}06_VLESS_gRPC_inbounds.json)
			jq .inbounds[0].settings.clients ${configPath}06_VLESS_gRPC_inbounds.json | jq -c '.[]' | while read -r user; do
				echoContent skyBlue "\n ---> 帐号：$(echo "${user}" | jq -r .email )_$(echo "${user}" | jq -r .id)"
				echo
				defaultBase64Code vlessgrpc $(echo "${user}" | jq -r .email) $(echo "${user}" | jq -r .id) "${currentHost}:${currentPort}" ${serviceName} ${currentAdd}
			done
		fi
	fi

	# trojan tcp
	if echo ${currentInstallProtocolType} | grep -q 4; then
		echoContent skyBlue "\n==================================  Trojan TLS  ==================================\n"
		jq .inbounds[0].settings.clients ${configPath}04_trojan_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
			echoContent skyBlue "\n ---> 帐号：$(echo "${user}" | jq -r .email )_$(echo "${user}" | jq -r .password)"
			echo
			defaultBase64Code trojan trojan $(echo "${user}" | jq -r .password) ${currentHost}
		done
	fi

	if echo ${currentInstallProtocolType} | grep -q 2; then
		echoContent skyBlue "\n================================  Trojan gRPC TLS  ================================\n"
		echoContent red "\n --->gRPC目前处于测试阶段，可能对你使用的客户端不兼容，如不能使用请忽略"
		local serviceName=$(jq -r .inbounds[0].streamSettings.grpcSettings.serviceName ${configPath}04_trojan_gRPC_inbounds.json)
		jq .inbounds[0].settings.clients ${configPath}04_trojan_gRPC_inbounds.json | jq -c '.[]' | while read -r user; do
			echoContent skyBlue "\n ---> 帐号：$(echo "${user}" | jq -r .email )_$(echo "${user}" | jq -r .password)"
			echo
			defaultBase64Code trojangrpc $(echo "${user}" | jq -r .email) $(echo "${user}" | jq -r .password) "${currentHost}:${currentPort}" ${serviceName} ${currentAdd}
		done
	fi

	if [[ -z ${show} ]]; then
		echoContent red " ---> 未安装"
	fi
}

# 更新伪装站
updateNginxBlog() {
	echoContent skyBlue "\n进度 $1/${totalProgress} : Replace the camouflage site"
	echoContent red "=============================================================="
	echoContent yellow "# If you need custom, please copy the template file manually /usr/share/nginx/html \n"
	echoContent yellow "1.Beginner's guide"
	echoContent yellow "2.Gaming website"
	echoContent yellow "3.Personal blog 01"
	echoContent yellow "4.Corporate station"
	echoContent yellow "5.Unlock encrypted music file templates[https://github.com/ix64/unlock-music]"
	echoContent yellow "6.mikutap[https://github.com/HFIProgramming/mikutap]"
	echoContent yellow "7.Enterprise Station 02"
	echoContent yellow "8.Personal blog 02"
	echoContent yellow "9.404 automatic jump baidu"
	echoContent red "=============================================================="
	read -r -p "请选择：" selectInstallNginxBlogType

	if [[ "${selectInstallNginxBlogType}" =~ ^[1-9]$ ]]; then
#		rm -rf /usr/share/nginx/html
		rm -rf /usr/share/nginx/*
		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /usr/share/nginx "https://raw.githubusercontent.com/oktest145/v2ray-agent/master/fodder/blog/unable/html${selectInstallNginxBlogType}.zip" >/dev/null
		else
			wget -c -P /usr/share/nginx "https://raw.githubusercontent.com/oktest145/v2ray-agent/master/fodder/blog/unable/html${selectInstallNginxBlogType}.zip" >/dev/null
		fi

		unzip -o "/usr/share/nginx/html${selectInstallNginxBlogType}.zip" -d /usr/share/nginx/html >/dev/null
		rm -f "/usr/share/nginx/html${selectInstallNginxBlogType}.zip*"
		echoContent green " ---> Replace the pseudo station successfully"
	else
		echoContent red " ---> Select errors, please choose again"
		updateNginxBlog
	fi
}

# 添加新端口
addCorePort() {
	echoContent skyBlue "\n功能 1/${totalProgress} : Add new port"
	echoContent red "\n=============================================================="
	echoContent yellow "# Precautions\n"
	echoContent yellow "Support batch addition"
	echoContent yellow "Does not affect the use of port 443"
	echoContent yellow "When viewing the account, only the account of the default port 443 will be displayed"
	echoContent yellow "No special characters are allowed, pay attention to the format of the comma"
	echoContent yellow "Entry example:2053,2083,2087\n"

	echoContent yellow "1.Adding ports"
	echoContent yellow "2.Delete port"
	echoContent red "=============================================================="
	read -r -p "please choose:" selectNewPortType
	if [[ "${selectNewPortType}" == "1" ]]; then
		read -r -p "Please enter the port number:" newPort
		if [[ -n "${newPort}" ]]; then

			while read -r port; do
				cat <<EOF >${configPath}02_dokodemodoor_inbounds_${port}.json
{
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": ${port},
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1",
        "port": 443,
        "network": "tcp",
        "followRedirect": false
      },
      "tag": "dokodemo-door-newPort-${port}"
    }
  ]
}
EOF
			done < <(echo "${newPort}" | tr ',' '\n')

			echoContent green " ---> Added successfully"
			reloadCore
		fi
	elif [[ "${selectNewPortType}" == "2" ]]; then

		ls ${configPath} | grep dokodemodoor | awk -F "[_]" '{print $4}' | awk -F "[.]" '{print ""NR""":"$1}'
		read -r -p "Please enter the port number to be deleted:" portIndex

		local dokoConfig=$(ls ${configPath} | grep dokodemodoor | awk '{print ""NR""":"$1}' | grep ${portIndex}":")
		if [[ -n "${dokoConfig}" ]]; then
			rm ${configPath}/$(echo "${dokoConfig}" | awk -F "[:]" '{print $2}')
			reloadCore
		else
			echoContent yellow "\n ---> Number input error, please choose again"
			addCorePort
		fi
	fi
}

# 卸载脚本
unInstall() {
	read -r -p "Do you confirm the uninstalled installation content?[y/n]:" unInstallStatus
	if [[ "${unInstallStatus}" != "y" ]]; then
		echoContent green " ---> Give up uninstallation"
		menu
		exit 0
	fi

	handleNginx stop
	if [[ -z $(pgrep -f "nginx") ]]; then
		echoContent green " ---> Stop nginx success"
	fi

	handleV2Ray stop
#	handleTrojanGo stop
	rm -rf /root/.acme.sh
	echoContent green " ---> Delete ACME.SH completion"
	rm -rf /etc/systemd/system/v2ray.service
	echoContent green " ---> Delete V2Ray and start self -starting."

	rm -rf /etc/systemd/system/trojan-go.service
	echoContent green " ---> Delete Trojan-GO boot self -started to complete"
	rm -rf /tmp/v2ray-agent-tls/*
	if [[ -d "/etc/v2ray-agent/tls" ]] && [[ -n $(find /etc/v2ray-agent/tls/ -name "*.key") ]] && [[ -n $(find /etc/v2ray-agent/tls/ -name "*.crt") ]]; then
		mv /etc/v2ray-agent/tls /tmp/v2ray-agent-tls
		if [[ -n $(find /tmp/v2ray-agent-tls -name '*.key') ]]; then
			echoContent yellow " ---> The backup certificate is successful, please pay attention to stay.[/tmp/v2ray-agent-tls]"
		fi
	fi

	rm -rf /etc/v2ray-agent
	rm -rf /etc/nginx/conf.d/alone.conf
	rm -rf /usr/bin/vasma
	rm -rf /usr/sbin/vasma
	echoContent green " ---> Uninstallation of shortcuts to complete"
	echoContent green " ---> Uninstall v2ray-agent脚本完成"
}

# 修改V2Ray CDN节点
updateV2RayCDN() {

	# todo 重构此方法
	echoContent skyBlue "\n进度 $1/${totalProgress} : Modify the CDN node"

	if [[ -n ${currentAdd} ]]; then
		echoContent red "=============================================================="
		echoContent yellow "1.CNAME www.digitalocean.com"
		echoContent yellow "2.CNAME www.cloudflare.com"
		echoContent yellow "3.CNAME hostmonit.com"
		echoContent yellow "4.Manually input"
		echoContent red "=============================================================="
		read -r -p "请选择:" selectCDNType
		case ${selectCDNType} in
		1)
			setDomain="www.digitalocean.com"
			;;
		2)
			setDomain="www.cloudflare.com"
			;;
		3)
			setDomain="hostmonit.com"
			;;
		4)
			read -r -p "Please enter to customize CDN IP or domain name:" setDomain
			;;
		esac

		if [[ -n ${setDomain} ]]; then
			if [[ -n ${currentAdd} ]]; then
				sed -i "s/\"${currentAdd}\"/\"${setDomain}\"/g" $(grep "${currentAdd}" -rl ${configPath}${frontingType}.json)
			fi
			if [[ $(jq -r .inbounds[0].settings.clients[0].add ${configPath}${frontingType}.json) == ${setDomain} ]]; then
				echoContent green " ---> CDN Modifications Successfully"
				reloadCore
			else
				echoContent red " ---> Modify CDN failed"
			fi

			# trojan
#			if [[ -d "/etc/v2ray-agent/trojan" ]] && [[ -f "/etc/v2ray-agent/trojan/config_full.json" ]]; then
#				add=$(jq -r .websocket.add /etc/v2ray-agent/trojan/config_full.json)
#				if [[ -n ${add} ]]; then
#					sed -i "s/${add}/${setDomain}/g" $(grep "${add}" -rl /etc/v2ray-agent/trojan/config_full.json)
#				fi
#			fi

#			if [[ -d "/etc/v2ray-agent/trojan" ]] && [[ -f "/etc/v2ray-agent/trojan/config_full.json" ]] && [[ $(jq -r .websocket.add /etc/v2ray-agent/trojan/config_full.json) == ${setDomain} ]]; then
#				echoContent green "\n ---> Trojan CDN修改成功"
#				handleTrojanGo stop
#				handleTrojanGo start
#			elif [[ -d "/etc/v2ray-agent/trojan" ]] && [[ -f "/etc/v2ray-agent/trojan/config_full.json" ]]; then
#				echoContent red " ---> 修改Trojan CDN失败"
#			fi
		fi
	else
		echoContent red " ---> Unpacking type"
	fi
}

# manageUser 用户管理
manageUser() {
	echoContent skyBlue "\n进度 $1/${totalProgress} : Multi -user management"
	echoContent skyBlue "-----------------------------------------------------"
	echoContent yellow "1.Add user"
	echoContent yellow "2.delete users"
	echoContent skyBlue "-----------------------------------------------------"
	read -r -p "please choose:" manageUserType
	if [[ "${manageUserType}" == "1" ]]; then
		addUser
	elif [[ "${manageUserType}" == "2" ]]; then
		removeUser
	else
		echoContent red " ---> wrong selection"
	fi
}

# 自定义uuid
customUUID() {
	read -r -p "Whether to customize UUID ？[y/n]:" customUUIDStatus
	echo
	if [[ "${customUUIDStatus}" == "y" ]]; then
		read -r -p "Please enter the legal UUID:" currentCustomUUID
		echo
		if [[ -z "${currentCustomUUID}" ]]; then
			echoContent red " ---> UUID must not be empty"
		else
			local repeat=
			jq -r -c '.inbounds[0].settings.clients[].id' ${configPath}${frontingType}.json | while read -r line; do
				if [[ "${line}" == "${currentCustomUUID}" ]]; then
					echo repeat >/tmp/v2ray-agent
				fi
			done
			if [[ -f "/tmp/v2ray-agent" && -n $(cat /tmp/v2ray-agent) ]]; then
				echoContent red " ---> UUID cannot be repeated"
				rm /tmp/v2ray-agent
				exit 0
			fi
		fi
	fi
}

# 自定义email
customUserEmail() {
	read -r -p "Whether to customize email ？[y/n]:" customEmailStatus
	echo
	if [[ "${customEmailStatus}" == "y" ]]; then
		read -r -p "Please enter the legal email:" currentCustomEmail
		echo
		if [[ -z "${currentCustomEmail}" ]]; then
			echoContent red " ---> email must not be empty"
		else
			local repeat=
			jq -r -c '.inbounds[0].settings.clients[].email' ${configPath}${frontingType}.json | while read -r line; do
				if [[ "${line}" == "${currentCustomEmail}" ]]; then
					echo repeat >/tmp/v2ray-agent
				fi
			done
			if [[ -f "/tmp/v2ray-agent" && -n $(cat /tmp/v2ray-agent) ]]; then
				echoContent red " ---> email cannot be repeated"
				rm /tmp/v2ray-agent
				exit 0
			fi
		fi
	fi
}

# 添加用户
addUser() {

	echoContent yellow "After adding a new user, you need to check the subscription again"
	read -r -p "Please enter the number of users to be added:" userNum
	echo
	if [[ -z ${userNum} || ${userNum} -le 0 ]]; then
		echoContent red " ---> Input is wrong, please re -enter"
		exit 0
	fi

	# 生成用户
	local users=
	local trojanGoUsers=
	if [[ "${userNum}" == "1" ]]; then
		customUUID
		customUserEmail
	fi

	while [[ ${userNum} -gt 0 ]]; do

		((userNum--)) || true
		if [[ -n "${currentCustomUUID}" ]]; then
			uuid=${currentCustomUUID}
		else
			uuid=$(${ctlPath} uuid)
		fi
		if [[ -n "${currentCustomEmail}" ]]; then
			email=${currentCustomEmail}
		else
			email=${currentHost}_${uuid}
		fi

		if [[ ${userNum} == 0 ]]; then

			users=${users}{\"id\":\"${uuid}\",\"flow\":\"xtls-rprx-direct\",\"email\":\"${email}\",\"alterId\":0}

			if echo ${currentInstallProtocolType} | grep -q 4; then
				trojanGoUsers=${trojanGoUsers}\"${uuid}\"
			fi
		else
			users=${users}{\"id\":\"${uuid}\",\"flow\":\"xtls-rprx-direct\",\"email\":\"${email}\",\"alterId\":0},

			if echo ${currentInstallProtocolType} | grep -q 4; then
				trojanGoUsers=${trojanGoUsers}\"${uuid}\",
			fi
		fi
	done

	#	兼容v2ray-core
	if [[ "${coreInstallType}" == "2" ]]; then
		#  | sed 's/"flow":"xtls-rprx-direct",/"alterId":1,/g')
		users="${users//\"flow\":\"xtls-rprx-direct\"\,/}"
	fi

	if echo ${currentInstallProtocolType} | grep -q 0; then
		local vlessUsers="${users//\,\"alterId\":0/}"

		local vlessTcpResult
		vlessTcpResult=$(jq -r '.inbounds[0].settings.clients += ['${vlessUsers}']' ${configPath}${frontingType}.json)
		echo "${vlessTcpResult}" | jq . >${configPath}${frontingType}.json
	fi

	if echo ${currentInstallProtocolType} | grep -q trojan; then
		local trojanXTLSUsers="${users//\,\"alterId\":0/}"
		trojanXTLSUsers=${trojanXTLSUsers//"id"/"password"}
		echo trojanXTLSUsers:${trojanXTLSUsers}
		local trojanXTLSResult
		trojanXTLSResult=$(jq -r '.inbounds[0].settings.clients += ['${trojanXTLSUsers}']' ${configPath}${frontingType}.json)
		echo "${trojanXTLSResult}" | jq . >${configPath}${frontingType}.json
	fi

	#	users="${users//"flow":"xtls-rprx-direct",/"alterId":1,}"

	if echo ${currentInstallProtocolType} | grep -q 1; then
		local vlessUsers="${users//\,\"alterId\":0/}"
		vlessUsers="${vlessUsers//\"flow\":\"xtls-rprx-direct\"\,/}"
		local vlessWsResult
		vlessWsResult=$(jq -r '.inbounds[0].settings.clients += ['${vlessUsers}']' ${configPath}03_VLESS_WS_inbounds.json)
		echo "${vlessWsResult}" | jq . >${configPath}03_VLESS_WS_inbounds.json
	fi

	if echo ${currentInstallProtocolType} | grep -q 2; then
		local trojangRPCUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"
		trojangRPCUsers="${trojangRPCUsers//\,\"alterId\":0/}"
		trojangRPCUsers=${trojangRPCUsers//"id"/"password"}

		local trojangRPCResult
		trojangRPCResult=$(jq -r '.inbounds[0].settings.clients += ['${trojangRPCUsers}']' ${configPath}04_trojan_gRPC_inbounds.json)
		echo "${trojangRPCResult}" | jq . >${configPath}04_trojan_gRPC_inbounds.json
	fi

	if echo ${currentInstallProtocolType} | grep -q 3; then
		local vmessUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"

		local vmessWsResult
		vmessWsResult=$(jq -r '.inbounds[0].settings.clients += ['${vmessUsers}']' ${configPath}05_VMess_WS_inbounds.json)
		echo "${vmessWsResult}" | jq . >${configPath}05_VMess_WS_inbounds.json
	fi

	if echo ${currentInstallProtocolType} | grep -q 5; then
		local vlessGRPCUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"
		vlessGRPCUsers="${vlessGRPCUsers//\,\"alterId\":0/}"

		local vlessGRPCResult
		vlessGRPCResult=$(jq -r '.inbounds[0].settings.clients += ['${vlessGRPCUsers}']' ${configPath}06_VLESS_gRPC_inbounds.json)
		echo "${vlessGRPCResult}" | jq . >${configPath}06_VLESS_gRPC_inbounds.json
	fi

	if echo ${currentInstallProtocolType} | grep -q 4; then
		local trojanUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"
		trojanUsers="${trojanUsers//id/password}"
		trojanUsers="${trojanUsers//\,\"alterId\":0/}"


		local trojanTCPResult
		trojanTCPResult=$(jq -r '.inbounds[0].settings.clients += ['${trojanUsers}']' ${configPath}04_trojan_TCP_inbounds.json)
		echo "${trojanTCPResult}" | jq . >${configPath}04_trojan_TCP_inbounds.json
	fi

#	if echo ${currentInstallProtocolType} | grep -q 4; then
#		local trojanResult
#		trojanResult=$(jq -r '.password += ['${trojanGoUsers}']' ${configPath}../../trojan/config_full.json)
#		echo "${trojanResult}" | jq . >${configPath}../../trojan/config_full.json
#		handleTrojanGo stop
#		handleTrojanGo start
#	fi

	reloadCore
	echoContent green " ---> 添加完成"
	showAccounts 1
}

# 移除用户
removeUser() {

	if echo ${currentInstallProtocolType} | grep -q 0 || echo ${currentInstallProtocolType} | grep -q trojan ; then
		jq -r -c .inbounds[0].settings.clients[].email ${configPath}${frontingType}.json | awk '{print NR""":"$0}'
		read -r -p "请选择要删除的用户编号[仅支持单个删除]:" delUserIndex
		if [[ $(jq -r '.inbounds[0].settings.clients|length' ${configPath}${frontingType}.json) -lt ${delUserIndex} ]]; then
			echoContent red " ---> 选择错误"
		else
			delUserIndex=$((${delUserIndex} - 1))
			local vlessTcpResult
			vlessTcpResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}${frontingType}.json)
			echo "${vlessTcpResult}" | jq . >${configPath}${frontingType}.json
		fi
	fi
	if [[ -n "${delUserIndex}" ]]; then
		if echo ${currentInstallProtocolType} | grep -q 1; then
			local vlessWSResult
			vlessWSResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}03_VLESS_WS_inbounds.json)
			echo "${vlessWSResult}" | jq . >${configPath}03_VLESS_WS_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 2; then
			local trojangRPCUsers
			trojangRPCUsers=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}04_trojan_gRPC_inbounds.json)
			echo "${trojangRPCUsers}" | jq . >${configPath}04_trojan_gRPC_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 3; then
			local vmessWSResult
			vmessWSResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}05_VMess_WS_inbounds.json)
			echo "${vmessWSResult}" | jq . >${configPath}05_VMess_WS_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 5; then
			local vlessGRPCResult
			vlessGRPCResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}06_VLESS_gRPC_inbounds.json)
			echo "${vlessGRPCResult}" | jq . >${configPath}06_VLESS_gRPC_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 4; then
			local trojanTCPResult
			trojanTCPResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}04_trojan_TCP_inbounds.json)
			echo "${trojanTCPResult}" | jq . >${configPath}04_trojan_TCP_inbounds.json
		fi

		reloadCore
	fi
}
# 更新脚本
updateV2RayAgent() {
	echoContent skyBlue "\n进度  $1/${totalProgress} : Update v2ray-agent脚本"
	rm -rf /etc/v2ray-agent/install.sh
	if wget --help | grep -q show-progress; then
		wget -c -q --show-progress -P /etc/v2ray-agent/ -N --no-check-certificate "https://raw.githubusercontent.com/oktest145/v2ray-agent/master/install.sh"
	else
		wget -c -q -P /etc/v2ray-agent/ -N --no-check-certificate "https://raw.githubusercontent.com/oktest145/v2ray-agent/master/install.sh"
	fi

	sudo chmod 700 /etc/v2ray-agent/install.sh
	local version=$(cat /etc/v2ray-agent/install.sh | grep 'current version：v' | awk -F "[v]" '{print $2}' | tail -n +2 | head -n 1 | awk -F "[\"]" '{print $1}')

	echoContent green "\n ---> update completed"
	echoContent yellow " ---> Please execute manually[vasma]Open the script"
	echoContent green " ---> current version:${version}\n"
	echoContent yellow "If the update is unsuccessful, please manually execute the following command\n"
	echoContent skyBlue "wget -P /root -N --no-check-certificate "https://raw.githubusercontent.com/oktest145/v2ray-agent/master/install.sh" && chmod 700 /root/install.sh && /root/install.sh"
	echo
	exit 0
}

# 安装BBR
bbrInstall() {
	echoContent red "\n=============================================================="
	echoContent green "[Ylx2016] mature works for BBR, DD script, address [https://github.com/ylx2016/linux- netSpeed], please familiar with"
	echoContent yellow "1.Install script [Recommended original BBR+FQ]"
	echoContent yellow "2.Returning Directory"
	echoContent red "=============================================================="
	read -r -p "请选择：" installBBRStatus
	if [[ "${installBBRStatus}" == "1" ]]; then
		wget -N --no-check-certificate "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh" && chmod +x tcp.sh && ./tcp.sh
	else
		menu
	fi
}

# 查看、检查日志
checkLog() {
	if [[ -z ${configPath} ]]; then
		echoContent red " ---> No installation directory is detected, please execute the content of the script"
	fi
	local logStatus=false
	if [[ -n $(cat ${configPath}00_log.json | grep access) ]]; then
		logStatus=true
	fi

	echoContent skyBlue "\n功能 $1/${totalProgress} : View log"
	echoContent red "\n=============================================================="
	echoContent yellow "# It is recommended to open the Access log in only debugging\n"

	if [[ "${logStatus}" == "false" ]]; then
		echoContent yellow "1.Open the Access log"
	else
		echoContent yellow "1.Turn off the Access log"
	fi

	echoContent yellow "2.Surveillance Access log"
	echoContent yellow "3.Surveillance Error log"
	echoContent yellow "4.View the time -to -time task log"
	echoContent yellow "5.View certificate installation log"
	echoContent yellow "6.Empty log"
	echoContent red "=============================================================="

	read -r -p "please choose:" selectAccessLogType
	local configPathLog=${configPath//conf\//}

	case ${selectAccessLogType} in
	1)
		if [[ "${logStatus}" == "false" ]]; then
			cat <<EOF >${configPath}00_log.json
{
  "log": {
  	"access":"${configPathLog}access.log",
    "error": "${configPathLog}error.log",
    "loglevel": "debug"
  }
}
EOF
		elif [[ "${logStatus}" == "true" ]]; then
			cat <<EOF >${configPath}00_log.json
{
  "log": {
    "error": "${configPathLog}error.log",
    "loglevel": "warning"
  }
}
EOF
		fi
		reloadCore
		checkLog 1
		;;
	2)
		tail -f ${configPathLog}access.log
		;;
	3)
		tail -f ${configPathLog}error.log
		;;
	4)
		tail -n 100 /etc/v2ray-agent/crontab_tls.log
		;;
	5)
		tail -n 100 /etc/v2ray-agent/tls/acme.log
		;;
	6)
		echo >${configPathLog}access.log
		echo >${configPathLog}error.log
		;;
	esac
}

# 脚本快捷方式
aliasInstall() {

	if [[ -f "$HOME/install.sh" ]] && [[ -d "/etc/v2ray-agent" ]] && grep <$HOME/install.sh -q "作者：oktest145"; then
		mv "$HOME/install.sh" /etc/v2ray-agent/install.sh
		local vasmaType=
		if [[ -d "/usr/bin/" ]] ; then
			if [[ ! -f "/usr/bin/vasma" ]];then
				ln -s /etc/v2ray-agent/install.sh /usr/bin/vasma
				chmod 700 /usr/bin/vasma
				vasmaType=true
			fi

			rm -rf "$HOME/install.sh"
		elif [[ -d "/usr/sbin" ]] ; then
			if [[ ! -f "/usr/sbin/vasma" ]];then
				ln -s /etc/v2ray-agent/install.sh /usr/sbin/vasma
				chmod 700 /usr/sbin/vasma
				vasmaType=true
			fi
			rm -rf "$HOME/install.sh"
		fi
		if [[ "${vasmaType}" == "true" ]];then
			echoContent green "The shortcut creation is successful and can be executed [VASMA] to re -open the script"
		fi
	fi
}

# 检查ipv6、ipv4
checkIPv6() {
	pingIPv6=$(ping6 -c 1 www.google.com | sed '2{s/[^(]*(//;s/).*//;q;}' | tail -n +2)
	if [[ -z "${pingIPv6}" ]]; then
		echoContent red " ---> Do not support IPv6"
		exit 0
	fi
}

# ipv6 分流
ipv6Routing() {
	if [[ -z "${configPath}" ]]; then
		echoContent red " ---> Not installed, please use scripts to install"
		menu
		exit 0
	fi

	checkIPv6
	echoContent skyBlue "\n function 1/${totalProgress} : IPv6 diversion"
	echoContent red "\n=============================================================="
	echoContent yellow "1.Add domain name"
	echoContent yellow "2.Uninstallation of IPv6 diversion"
	echoContent red "=============================================================="
	read -r -p "请选择:" ipv6Status
	if [[ "${ipv6Status}" == "1" ]]; then
		echoContent red "=============================================================="
		echoContent yellow "# Precautions\n"
		echoContent yellow "1.The rules only support the list of predefined domains[https://github.com/v2fly/domain-list-community]"
		echoContent yellow "2.Detailed documentation[https://www.v2fly.org/config/routing.html]"
		echoContent yellow "3.If the kernel launch fails, please check the domain name after checking the domain nameh fails, please check the domain name after checking the domain name"
		echoContent yellow "4.No special characters are allowed, pay attention to the format of the comma"
		echoContent yellow "5.Every time you add it, it will be re -added, and the last domain name will not be retained"
		echoContent yellow "6.Entry example:google,youtube,facebook\n"
		read -r -p "Please enter the domain name according to the example above:" domainList

		if [[ -f "${configPath}09_routing.json" ]];then

			unInstallRouting IPv6-out

			routing=$(jq -r '.routing.rules += [{"type":"field","domain":["geosite:'${domainList//,/\",\"geosite:}'"],"outboundTag":"IPv6-out"}]' ${configPath}09_routing.json)

			echo "${routing}"|jq . >${configPath}09_routing.json

		else
			cat <<EOF >${configPath}09_routing.json
{
    "routing":{
        "domainStrategy": "IPOnDemand",
        "rules": [
          {
            "type": "field",
            "domain": [
            	"geosite:${domainList//,/\",\"geosite:}"
            ],
            "outboundTag": "IPv6-out"
          }
        ]
  }
}
EOF
fi

		unInstallOutbounds IPv6-out

		outbounds=$(jq -r '.outbounds += [{"protocol":"freedom","settings":{"domainStrategy":"UseIPv6"},"tag":"IPv6-out"}]' ${configPath}10_ipv4_outbounds.json)

		echo "${outbounds}"|jq . >${configPath}10_ipv4_outbounds.json

		echoContent green " ---> Added successfully"

	elif [[ "${ipv6Status}" == "2" ]]; then

		unInstallRouting IPv6-out

		unInstallOutbounds IPv6-out

		echoContent green " ---> IPv6 Diversion Uninstallation Success"
	else
		echoContent red " ---> wrong selection"
		exit 0
	fi

	reloadCore
}

# bt下载管理
btTools() {
	if [[ -z "${configPath}" ]]; then
		echoContent red " ---> Not installed, please use scripts to install"
		menu
		exit 0
	fi

	echoContent skyBlue "\n功能 1/${totalProgress} : BT download management"
	echoContent red "\n=============================================================="

	if [[ -f ${configPath}09_routing.json ]] && grep -q bittorrent < ${configPath}09_routing.json;then
		echoContent yellow "Current status: disabled"
	else
		echoContent yellow "Current status: No disabled"
	fi

	echoContent yellow "1.Disable"
	echoContent yellow "2.Open"
	echoContent red "=============================================================="
	read -r -p "请选择:" btStatus
	if [[ "${btStatus}" == "1" ]]; then

		if [[ -f "${configPath}09_routing.json" ]];then

			unInstallRouting blackhole-out

			routing=$(jq -r '.routing.rules += [{"type":"field","outboundTag":"blackhole-out","protocol":["bittorrent"]}]' ${configPath}09_routing.json)

			echo "${routing}"|jq . >${configPath}09_routing.json

		else
			cat <<EOF >${configPath}09_routing.json
{
    "routing":{
        "domainStrategy": "IPOnDemand",
        "rules": [
          {
            "type": "field",
            "outboundTag": "blackhole-out",
            "protocol": [ "bittorrent" ]
          }
        ]
  }
}
EOF
fi

		installSniffing

		unInstallOutbounds blackhole-out

		outbounds=$(jq -r '.outbounds += [{"protocol":"blackhole","tag":"blackhole-out"}]' ${configPath}10_ipv4_outbounds.json)

		echo "${outbounds}"|jq . >${configPath}10_ipv4_outbounds.json



		echoContent green " ---> BT download banned success"

	elif [[ "${btStatus}" == "2" ]]; then

		unInstallSniffing

		unInstallRouting blackhole-out

		unInstallOutbounds blackhole-out

		echoContent green " ---> BT download is successful"
	else
		echoContent red " ---> wrong selection"
		exit 0
	fi

	reloadCore
}

# 根据tag卸载Routing
unInstallRouting(){
	local tag=$1

	if [[ -f "${configPath}09_routing.json" ]];then
		local routing=
		if grep -q "${tag}" ${configPath}09_routing.json;then
			local index=$(jq .routing.rules[].outboundTag ${configPath}09_routing.json|awk '{print ""NR""":"$0}'|grep "${tag}"|awk -F "[:]" '{print $1}'|head -1)
			if [[ ${index} -gt 0 ]];then
				routing=$(jq -r 'del(.routing.rules['$(expr ${index} - 1)'])' ${configPath}09_routing.json)
				echo "${routing}" |jq . >${configPath}09_routing.json
			fi
		fi
	fi
}

# 根据tag卸载出站
unInstallOutbounds(){
	local tag=$1

	if grep -q "${tag}" ${configPath}10_ipv4_outbounds.json;then
		local ipv6OutIndex=$(jq .outbounds[].tag ${configPath}10_ipv4_outbounds.json|awk '{print ""NR""":"$0}'|grep "${tag}"|awk -F "[:]" '{print $1}'|head -1)
		if [[ ${ipv6OutIndex} -gt 0 ]];then
			routing=$(jq -r 'del(.outbounds['$(expr ${ipv6OutIndex} - 1)'])' ${configPath}10_ipv4_outbounds.json)
			echo "${routing}" |jq . >${configPath}10_ipv4_outbounds.json
		fi
	fi

}

# 卸载嗅探
unInstallSniffing(){
	ls ${configPath}|grep inbounds.json|while read -r inbound;do
		sniffing=$(jq -r 'del(.inbounds[0].sniffing)' ${configPath}${inbound})
		echo "${sniffing}" |jq . >${configPath}${inbound}
	done
}

# 安装嗅探
installSniffing(){
	ls ${configPath}|grep inbounds.json|while read -r inbound;do
		sniffing=$(jq -r '.inbounds[0].sniffing = {"enabled":true,"destOverride":["http","tls"]}' ${configPath}${inbound})
		echo "${sniffing}" |jq . >${configPath}${inbound}
	done
}

# warp分流
warpRouting(){
	echoContent skyBlue "\n进度  $1/${totalProgress} : Warp diversion"

	# 安装warp
	if [[ -z $(which warp-cli) ]];then
		echo
		read -r -p "WARP is not installed, is it installed ？[y/n]:" installCloudflareWarpStatus
		if [[ "${installCloudflareWarpStatus}" == "y" ]];then
			installWarp
		else
			echoContent yellow " ---> 放弃安装"
			exit 0
		fi
	fi

	echoContent red "\n=============================================================="
	echoContent yellow "1.Add domain name"
	echoContent yellow "2.Uninstalled warp diversion"
	echoContent red "=============================================================="
	read -r -p "请选择:" warpStatus
	if [[ "${warpStatus}" == "1" ]]; then
		echoContent red "=============================================================="
		echoContent yellow "# Precautions\n"
		echoContent yellow "1.The rules only support the list of predefined domains[https://github.com/v2fly/domain-list-community]"
		echoContent yellow "2.Detailed documentation[https://www.v2fly.org/config/routing.html]"
		echoContent yellow "3.You can only divert traffic to warp, not specified as IPv4 or IPv6"
		echoContent yellow "4.If the kernel launch fails, please check the domain name after checking the domain name"
		echoContent yellow "5.No special characters are allowed, pay attention to the format of the comma"
		echoContent yellow "6.Every time you add it, it will be re -added, and the last domain name will not be retained"
		echoContent yellow "7.Entry example:google,youtube,facebook\n"
		read -r -p "Please enter the domain name according to the example above:" domainList

		if [[ -f "${configPath}09_routing.json" ]];then
			unInstallRouting warp-socks-out

			routing=$(jq -r '.routing.rules += [{"type":"field","domain":["geosite:'${domainList//,/\",\"geosite:}'"],"outboundTag":"warp-socks-out"}]' ${configPath}09_routing.json)

			echo "${routing}"|jq . >${configPath}09_routing.json

		else
			cat <<EOF >${configPath}09_routing.json
{
    "routing":{
        "domainStrategy": "IPOnDemand",
        "rules": [
          {
            "type": "field",
            "domain": [
            	"geosite:${domainList//,/\",\"geosite:}"
            ],
            "outboundTag": "warp-socks-out"
          }
        ]
  }
}
EOF
		fi
		unInstallOutbounds warp-socks-out

		local outbounds=$(jq -r '.outbounds += [{"protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":31303}]},"tag":"warp-socks-out"}]' ${configPath}10_ipv4_outbounds.json)

		echo "${outbounds}"|jq . >${configPath}10_ipv4_outbounds.json

		echoContent green " ---> Added successfully"

	elif [[ "${warpStatus}" == "2" ]]; then
		unInstallRouting warp-socks-out

		unInstallOutbounds warp-socks-out

		echoContent green " ---> warpDiversionUninstallationSuccess"
	else
		echoContent red " ---> wrong selection"
		exit 0
	fi
	reloadCore
}
# 流媒体工具箱
streamingToolbox() {
	echoContent skyBlue "\N function 1/${totalProgress} : Streaming toolbox"
	echoContent red "\n=============================================================="
	echoContent yellow "1.Netflix detection"
	echoContent yellow "2.Any door floor -to -floor unlock Netflix"
	echoContent yellow "3.DNS unlock streaming media"
	read -r -p "please choose:" selectType

	case ${selectType} in
	1)
		checkNetflix
		;;
	2)
		dokodemoDoorUnblockNetflix
		;;
	3)
		dnsUnlockNetflix
		;;
	esac

}

# 任意门解锁netflix
dokodemoDoorUnblockNetflix() {
	echoContent skyBlue "\n功能 1/${totalProgress} : Any door floor -to -floor unlock Netflix"
	echoContent red "\n=============================================================="
	echoContent yellow "# Precautionsautions"
	echoContent yellow "Unlock the detailed explanation of any door, please check this article[https://github.com/oktest145/v2ray-agent/blob/master/documents/netflix/dokodemo-unblock_netflix.md]\n"

	echoContent yellow "1.Add out of the station
	echoContent yellow "2.Add
	echoContent yellow "3.Uninstalled"
	read -r -p "please choose:" selectType

	case ${selectType} in
	1)
		setDokodemoDoorUnblockNetflixOutbounds
		;;
	2)
		setDokodemoDoorUnblockNetflixInbounds
		;;
	3)
		removeDokodemoDoorUnblockNetflix
		;;
	esac
}

# 设置任意门解锁Netflix【出站】
setDokodemoDoorUnblockNetflixOutbounds() {
	read -r -p "Please enter unlock netflix VPS IP:" setIP
	if [[ -n "${setIP}" ]]; then

		unInstallOutbounds netflix-80
		unInstallOutbounds netflix-443

		outbounds=$(jq -r '.outbounds += [{"tag":"netflix-80","protocol":"freedom","settings":{"domainStrategy":"AsIs","redirect":"'${setIP}':22387"}},{"tag":"netflix-443","protocol":"freedom","settings":{"domainStrategy":"AsIs","redirect":"'${setIP}':22388"}}]' ${configPath}10_ipv4_outbounds.json)

		echo "${outbounds}"|jq . >${configPath}10_ipv4_outbounds.json

		if [[ -f "${configPath}09_routing.json" ]] ;then
			unInstallRouting netflix-80
			unInstallRouting netflix-443

			local routing=$(jq -r '.routing.rules += [{"type":"field","port":80,"domain":["ip.sb","geosite:netflix"],"outboundTag":"netflix-80"},{"type":"field","port":443,"domain":["ip.sb","geosite:netflix"],"outboundTag":"netflix-443"}]' ${configPath}09_routing.json)
			echo "${routing}"|jq . >${configPath}09_routing.json
		else
			cat <<EOF >${configPath}09_routing.json
{
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "port": 80,
        "domain": [
          "ip.sb",
          "geosite:netflix"
        ],
        "outboundTag": "netflix-80"
      },
      {
        "type": "field",
        "port": 443,
        "domain": [
          "ip.sb",
          "geosite:netflix"
        ],
        "outboundTag": "netflix-443"
      }
    ]
  }
}
EOF
		fi
		reloadCore
		echoContent green " ---> Add netflix"
#		echoContent yellow " ---> Related nodes that do not support Trojan"
		exit 0
	fi
	echoContent red " ---> IP must not be empty"
}

# 设置任意门解锁Netflix【入站】
setDokodemoDoorUnblockNetflixInbounds() {

	echoContent skyBlue "\n功能 1/${totalProgress} : Add the door to add to the station"
	echoContent red "\n=============================================================="
	echoContent yellow "# Precautions\n"
	echoContent yellow "Support batch addition"
	echoContent yellow "No special characters are allowed, pay attention to the format of the comma"
	echoContent yellow "Entry example:1.1.1.1,1.1.1.2\n"
	read -r -p "Please enter the allow to access the unlock netflix vps的IP:" setIPs
	if [[ -n "${setIPs}" ]]; then
		cat <<EOF >${configPath}01_netflix_inbounds.json
{
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": 22387,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "0.0.0.0",
        "port": 80,
        "network": "tcp",
        "followRedirect": false
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http"
        ]
      },
      "tag": "unblock-80"
    },
    {
      "listen": "0.0.0.0",
      "port": 22388,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "0.0.0.0",
        "port": 443,
        "network": "tcp",
        "followRedirect": false
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "tls"
        ]
      },
      "tag": "unblock-443"
    }
  ]
}
EOF

	cat <<EOF >${configPath}10_ipv4_outbounds.json
{
    "outbounds":[
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv4"
            },
            "tag":"IPv4-out"
        },
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv6"
            },
            "tag":"IPv6-out"
        },
        {
            "protocol":"blackhole",
            "tag":"blackhole-out"
        }
    ]
}
EOF

		cat <<EOF >${configPath}09_routing.json
{
  "routing": {
    "rules": [
      {
        "source": [],
        "type": "field",
        "inboundTag": [
          "unblock-80",
          "unblock-443"
        ],
        "outboundTag": "direct"
      },
      {
        "domains": [
        	"geosite:netflix"
        ],
        "type": "field",
        "inboundTag": [
          "unblock-80",
          "unblock-443"
        ],
        "outboundTag": "blackhole-out"
      }
    ]
  }
}
EOF
		local ips=
		while read -r ip; do
			if [[ -z ${ips} ]];then
				ips=\"${ip}\"
			else
				ips=${ips},\"${ip}\"
			fi
		done< <(echo ${setIPs}|tr ',' '\n')

		local routing=$(jq -r '.routing.rules[0].source += ['${ips}']' ${configPath}09_routing.json)
		echo "${routing}" | jq . >${configPath}09_routing.json
		reloadCore
		echoContent green " ---> Add the landing station to unlock the success of Netflix"
		exit 0
	fi
	echoContent red " ---> IP must not be empty"
}

# 移除任意门解锁Netflix
removeDokodemoDoorUnblockNetflix() {

	unInstallOutbounds netflix-80
	unInstallOutbounds netflix-443
	unInstallRouting netflix-80
	unInstallRouting netflix-443
	rm -rf ${configPath}01_netflix_inbounds.json

	reloadCore
	echoContent green " ---> Unload"
}

# 重启核心
reloadCore() {
	if [[ "${coreInstallType}" == "1" ]]; then
		handleXray stop
		handleXray start
	elif [[ "${coreInstallType}" == "2" || "${coreInstallType}" == "3" ]]; then
		handleV2Ray stop
		handleV2Ray start
	fi
}

# 检查 vps是否支持Netflix
checkNetflix() {
	echoContent red "\n"
	echoContent yellow " 1.You can only detect whether the VPS supports Netflix"
	echoContent yellow " 2.Can't detect whether the proxy configuration DNS is unlocked whether it supports Netflix"
	echoContent yellow " 3.Can detect whether the VPS configuration DNS is unlocked whether it supports Netflix\n"
	echoContent skyBlue " ---> checking"
	netflixResult=$(curl -s -m 2 https://www.netflix.com | grep "Not Available")
	if [[ -n ${netflixResult} ]]; then
		echoContent red " ---> Netflix is not available"
		exit 0
	fi

	netflixResult=$(curl -s -m 2 https://www.netflix.com | grep "NSEZ-403")
	if [[ -n ${netflixResult} ]]; then
		echoContent red " ---> Netflix is not available"
		exit 0
	fi

	echoContent skyBlue " ---> Detect whether the desperate poison can be played"
	result=$(curl -s -m 2 https://www.netflix.com/title/70143836 | grep "page-404")
	if [[ -n ${result} ]]; then
		echoContent green " ---> You can only watch homemade dramas"
		exit 0
	fi
	echoContent green " ---> Netflix unlock"
	exit 0
}

# dns解锁Netflix
dnsUnlockNetflix() {
	echoContent skyBlue "\nFunction 1/${totalProgress} : DNS unlock netflix"
	echoContent red "\n=============================================================="
	echoContent yellow "1.Add to"
	echoContent yellow "2.Uninstalled"
	read -r -p "please choose:" selectType

	case ${selectType} in
	1)
		setUnlockDNS
		;;
	2)
		removeUnlockDNS
		;;
	esac
}

# 设置dns
setUnlockDNS() {
	read -r -p "Please enter the unlocked DNS of Netflix:" setDNS
	if [[ -n ${setDNS} ]]; then
		cat <<EOF >${configPath}11_dns.json
{
	"dns": {
		"servers": [
			{
				"address": "${setDNS}",
				"port": 53,
				"domains": [
					"geosite:netflix",
					"geosite:bahamut",
					"geosite:hulu",
					"geosite:hbo",
					"geosite:disney",
					"geosite:bbc",
					"geosite:4chan",
					"geosite:fox",
					"geosite:abema",
					"geosite:dmm",
					"geosite:niconico",
					"geosite:pixiv",
					"geosite:bilibili",
					"geosite:viu"
				]
			},
		"localhost"
		]
	}
}
EOF
		reloadCore

		echoContent green "\n ---> DNS unlocking is successful, the setting is true-Go无效"
		echoContent yellow "\n ---> If you can't watch it yet, you can try the following two solutions"
		echoContent yellow " 1.Restart VPS"
		echoContent yellow " 2.After uninstalling the DNS unlock, modify the local ones[/etc/resolv.conf]DNS设置并重启vps\n"
	else
		echoContent red " ---> DNS must not be empty"
	fi
	exit 0
}

# 移除Netflix解锁
removeUnlockDNS() {
	cat <<EOF >${configPath}11_dns.json
{
	"dns": {
		"servers": [
			"localhost"
		]
	}
}
EOF
	reloadCore

	echoContent green " ---> Unload"

	exit 0
}

# v2ray-core个性化安装
customV2RayInstall() {
	echoContent skyBlue "\n========================Personalized installation============================"
	echoContent yellow "VLESS is pre -set, you must install 0. If you only need to install 0, you can press Enter"
	if [[ "${selectCoreType}" == "2" ]]; then
		echoContent yellow "0.VLESS+TLS+TCP"
	else
		echoContent yellow "0.VLESS+TLS/XTLS+TCP"
	fi

	echoContent yellow "1.VLESS+TLS+WS[CDN]"
	echoContent yellow "2.VMess+TLS+TCP"
	echoContent yellow "3.VMess+TLS+WS[CDN]"
#	echoContent yellow "4.Trojan、Trojan+WS[CDN]"
	echoContent yellow "4.Trojan"
	echoContent yellow "5.VLESS+TLS+gRPC[CDN]"
	read -r -p "Please select [Multiple choices], [for example: 123]:" selectCustomInstallType
	echoContent skyBlue "--------------------------------------------------------------"
	if [[ -z ${selectCustomInstallType} ]]; then
		selectCustomInstallType=0
	fi
	if [[ "${selectCustomInstallType}" =~ ^[0-5]+$ ]]; then
		cleanUp xrayClean
		totalProgress=17
		installTools 1
		# 申请tls
		initTLSNginxConfig 2
		installTLS 3
		handleNginx stop
		initNginxConfig 4
		# 随机path
		if echo ${selectCustomInstallType} | grep -q 1 || echo ${selectCustomInstallType} | grep -q 3 || echo ${selectCustomInstallType} | grep -q 4; then
			randomPathFunction 5
			customCDNIP 6
		fi
		nginxBlog 7
		updateRedirectNginxConf
		handleNginx start

		# 安装V2Ray
		installV2Ray 8
		installV2RayService 9
		initV2RayConfig custom 10
		cleanUp xrayDel
#		if echo ${selectCustomInstallType} | grep -q 4; then
#			installTrojanGo 11
#			installTrojanService 12
#			initTrojanGoConfig 13
#			handleTrojanGo stop
#			handleTrojanGo start
#		else
#			# 这里需要删除trojan的服务
#			handleTrojanGo stop
#			rm -rf /etc/v2ray-agent/trojan/*
#			rm -rf /etc/systemd/system/trojan-go.service
#		fi
		installCronTLS 14
		handleV2Ray stop
		handleV2Ray start
		# 生成账号
		checkGFWStatue 15
		showAccounts 16
	else
		echoContent red " ---> Enter illegal input"
		customV2RayInstall
	fi
}

# Xray-core个性化安装
customXrayInstall() {
	echoContent skyBlue "\n========================Personalized installation============================"
	echoContent yellow "VLESS front, default installation 0, if you only need to install 0, you can only choose 0"
	echoContent yellow "0.VLESS+TLS/XTLS+TCP"
	echoContent yellow "1.VLESS+TLS+WS[CDN]"
	echoContent yellow "2.Trojan+TLS+gRPC[CDN]"
	echoContent yellow "3.VMess+TLS+WS[CDN]"
	# echoContent yellow "4.Trojan、Trojan+WS[CDN]"
	echoContent yellow "4.Trojan"
	echoContent yellow "5.VLESS+TLS+gRPC[CDN]"
	read -r -p "please choose[Choice]，[E.g:123]:" selectCustomInstallType
	echoContent skyBlue "--------------------------------------------------------------"
	if [[ -z ${selectCustomInstallType} ]]; then
		echoContent red " ---> Don't be empty"
		customXrayInstall
	elif [[ "${selectCustomInstallType}" =~ ^[0-5]+$ ]]; then
		cleanUp v2rayClean
		totalProgress=17
		installTools 1
		# 申请tls
		initTLSNginxConfig 2
		installTLS 3
		handleNginx stop
		initNginxConfig 4
		# 随机path
		if echo "${selectCustomInstallType}" | grep -q 1 || echo "${selectCustomInstallType}" | grep -q 2 || echo "${selectCustomInstallType}" | grep -q 3 || echo "${selectCustomInstallType}" | grep -q 5; then
			randomPathFunction 5
			customCDNIP 6
		fi
		nginxBlog 7
		updateRedirectNginxConf
		handleNginx start

		# 安装V2Ray
		installXray 8
		installXrayService 9
		initXrayConfig custom 10
		cleanUp v2rayDel
		if echo "${selectCustomInstallType}" | grep -q 4; then
#			installTrojanGo 11
#			installTrojanService 12
#			initTrojanGoConfig 13
#			handleTrojanGo stop
#			handleTrojanGo start
			echo
		else
			# 这里需要删除trojan的服务
#			handleTrojanGo stop
#			rm -rf /etc/v2ray-agent/trojan/*
#			rm -rf /etc/systemd/system/trojan-go.service
			echo
		fi

		installCronTLS 14
		handleXray stop
		handleXray start
		# 生成账号
		checkGFWStatue 15
		showAccounts 16
	else
		echoContent red " ---> Enter illegal input"
		customXrayInstall
	fi
}

# 选择核心安装---v2ray-core、xray-core、锁定版本的v2ray-core[xtls]
selectCoreInstall() {
	echoContent skyBlue "\n功能 1/${totalProgress} : Choose the core installation"
	echoContent red "\n=============================================================="
	echoContent yellow "1.Xray-core"
	echoContent yellow "2.v2ray-core"
	echoContent red "=============================================================="
	read -r -p "please choose:" selectCoreType
	case ${selectCoreType} in
	1)
		if [[ "${selectInstallType}" == "2" ]]; then
			customXrayInstall
		else
			xrayCoreInstall
		fi
		;;
	2)
		v2rayCoreVersion=
		if [[ "${selectInstallType}" == "2" ]]; then
			customV2RayInstall
		else
			v2rayCoreInstall
		fi
		;;
	3)
		v2rayCoreVersion=v4.32.1
		if [[ "${selectInstallType}" == "2" ]]; then
			customV2RayInstall
		else
			v2rayCoreInstall
		fi
		;;
	*)
		echoContent red ' ---> 选择错误，重新选择'
		selectCoreInstall
		;;
	esac
}

# v2ray-core 安装
v2rayCoreInstall() {
	cleanUp xrayClean
	selectCustomInstallType=
	totalProgress=17
	installTools 2
	# 申请tls
	initTLSNginxConfig 3
	installTLS 4
	handleNginx stop
	initNginxConfig 5
	randomPathFunction 6
	# 安装V2Ray
	installV2Ray 7
	installV2RayService 8
	customCDNIP 11
	initV2RayConfig all 12
	cleanUp xrayDel
	installCronTLS 14
	nginxBlog 15
	updateRedirectNginxConf
	handleV2Ray stop
	sleep 2
	handleV2Ray start
	handleNginx start
	# 生成账号
	checkGFWStatue 16
	showAccounts 17
}

# xray-core 安装
xrayCoreInstall() {
	cleanUp v2rayClean
	selectCustomInstallType=
	totalProgress=17
	installTools 2
	# 申请tls
	initTLSNginxConfig 3
	installTLS 4
	handleNginx stop
	initNginxConfig 5
	randomPathFunction 6
	# 安装Xray
	handleV2Ray stop
	installXray 7
	installXrayService 8
#	installTrojanGo 9
#	installTrojanService 10
	customCDNIP 11
	initXrayConfig all 12
	cleanUp v2rayDel
#	initTrojanGoConfig 13
	installCronTLS 14
	nginxBlog 15
	updateRedirectNginxConf
	handleXray stop
	sleep 2
	handleXray start

	handleNginx start
#	handleTrojanGo stop
#	sleep 1
#	handleTrojanGo start
	# 生成账号
	checkGFWStatue 16
	showAccounts 17
}

# 核心管理
coreVersionManageMenu() {

	if [[ -z "${coreInstallType}" ]]; then
		echoContent red "\n ---> No installation directory is detected, please execute the content of the script"
		menu
		exit 0
	fi
	if [[ "${coreInstallType}" == "1" ]]; then
		xrayVersionManageMenu 1
	elif [[ "${coreInstallType}" == "2" ]]; then
		v2rayCoreVersion=
		v2rayVersionManageMenu 1

	elif [[ "${coreInstallType}" == "3" ]]; then
		v2rayCoreVersion=v4.32.1
		v2rayVersionManageMenu 1
	fi
}
# 定时任务检查证书
cronRenewTLS() {
	if [[ "${renewTLS}" == "RenewTLS" ]]; then
		renewalTLS
		exit 0
	fi
}
# 账号管理
manageAccount() {
	echoContent skyBlue "\nFunction 1/${totalProgress} : Account management"
	echoContent red "\n=============================================================="
	echoContent yellow "# After deleting and adding an account at a time, you need to check the subscription to generate a subscription\n"
	echoContent yellow "1.View account number"
	echoContent yellow "2.View subscription subscription subscription"
	echoContent yellow "3.Add useruser"
	echoContent yellow "4.delete users"
	echoContent red "=============================================================="
	read -r -p "please enter:" manageAccountStatus
	if [[ "${manageAccountStatus}" == "1" ]]; then
		showAccounts 1
	elif [[ "${manageAccountStatus}" == "2" ]]; then
		subscribe 1
	elif [[ "${manageAccountStatus}" == "3" ]]; then
		addUser
	elif [[ "${manageAccountStatus}" == "4" ]]; then
		removeUser
	else
		echoContent red " ---> wrong selection"
	fi
}

# 订阅
subscribe() {
	if [[ -n "${configPath}" ]]; then
		echoContent skyBlue "-------------------------Remark---------------------------------"
		echoContent yellow "# View subscriptions will be re -generated when subscribing"
		echoContent yellow "# Each time you add and delete your account, you need to review the subscription"
		rm -rf /etc/v2ray-agent/subscribe/*
		rm -rf /etc/v2ray-agent/subscribe_tmp/*
		showAccounts >/dev/null
		mv /etc/v2ray-agent/subscribe_tmp/* /etc/v2ray-agent/subscribe/

		if [[ -n $(ls /etc/v2ray-agent/subscribe) ]]; then
			ls /etc/v2ray-agent/subscribe | while read -r email; do
				local base64Result=$(base64 -w 0 /etc/v2ray-agent/subscribe/${email})
				echo ${base64Result} >"/etc/v2ray-agent/subscribe/${email}"
				echoContent skyBlue "--------------------------------------------------------------"
				echoContent yellow "email：$(echo "${email}" | awk -F "[_]" '{print $1}')\n"
				echoContent yellow "url：https://${currentHost}/s/${email}\n"
				echoContent yellow "在线二维码：https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=https://${currentHost}/s/${email}\n"
				echo "https://${currentHost}/s/${email}" | qrencode -s 10 -m 1 -t UTF8
				echoContent skyBlue "--------------------------------------------------------------"
			done
		fi
	else
		echoContent red " ---> Not Installed"
	fi
}

# 主菜单
menu() {
	cd "$HOME" || exit
	echoContent red "\n=============================================================="
	echoContent green "Author: oktest145"
	echoContent green "Current version: V2.5.20"
	echoContent green "Github：https://github.com/oktest145/v2ray-agent"
	echoContent green "Description: Bayi A total of savings script\c"
	showInstallStatus
	echoContent red "\n=============================================================="
	if [[ -n "${coreInstallType}" ]]; then
		echoContent yellow "1.re-install"
	else
		echoContent yellow "1.Install"
	fi

	echoContent yellow "2.Any combination installation"
	if echo ${currentInstallProtocolType} | grep -q trojan; then
		echoContent yellow "3.Switch vless[XTLS]"
	elif echo ${currentInstallProtocolType} | grep -q 0;then
		echoContent yellow "3.Switch Trojan[XTLS]"
	fi
	echoContent skyBlue "-------------------------Tool management-----------------------------"
	echoContent yellow "4.Account management"
	echoContent yellow "5.Replace the camouflage station"
	echoContent yellow "6.Update certificate"
	echoContent yellow "7.Replace the CDN node"
	echoContent yellow "8.IPv6 diversion"
	echoContent yellow "9.Warp diversion[不可用]"
	echoContent yellow "10.Streaming tool"
	echoContent yellow "11.Add new port"
	echoContent yellow "12.BT download management"
	echoContent skyBlue "-------------------------Version management-----------------------------"
	echoContent yellow "13.core management"
	echoContent yellow "14.Renewal writer"
	echoContent yellow "15.Install BBR, DD script"
	echoContent skyBlue "-------------------------Script management-----------------------------"
	echoContent yellow "16.View log"
	echoContent yellow "17.Uninstall"
	echoContent red "=============================================================="
	mkdirTools
	aliasInstall
	read -r -p "please choose:" selectInstallType
	case ${selectInstallType} in
	1)
		selectCoreInstall
		;;
	2)
		selectCoreInstall
		;;
	3)
		initXrayFrontingConfig 1
		;;
	4)
		manageAccount 1
		;;
	5)
		updateNginxBlog 1
		;;
	6)
		renewalTLS 1
		;;
	7)
		updateV2RayCDN 1
		;;
	8)
		ipv6Routing 1
		;;
#	9)
#		warpRouting 1
#		;;
	10)
		streamingToolbox 1
		;;
	11)
		addCorePort 1
		;;
	12)
		btTools 1
		;;
	13)
		coreVersionManageMenu 1
		;;
	14)
		updateV2RayAgent 1
		;;
	15)
		bbrInstall
		;;
	16)
		checkLog 1
		;;
	17)
		unInstall 1
		;;
	esac
}
cronRenewTLS
menu
