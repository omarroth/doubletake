# bash completion for doubletake and doubletake-ctl; requires bash-completion.

_doubletake_complete_words()
{
    # These fixed word lists contain no spaces inside individual candidates.
    # shellcheck disable=SC2207
    COMPREPLY=( $(compgen -W "$1" -- "$cur") )
    return 0
}

_doubletake_complete_flags()
{
    local -a options=("$@")
    if [[ $cur == --* ]]; then
        options=("${options[@]/#-/--}")
    fi
    _doubletake_complete_words "${options[*]}"
}

_doubletake_complete_value()
{
    case $option in
        hwaccel) _doubletake_complete_words 'auto nvenc vaapi v4l2 openh264 none' ;;
        video-codec) _doubletake_complete_words 'auto h264 hevc' ;;
        audio-sink|audio-source) _doubletake_complete_words 'output monitor' ;;
        cred-backend) _doubletake_complete_words 'file keyring' ;;
        resolution|s) _doubletake_complete_words 'max 1280x720 1920x1080 2560x1440 3840x2160' ;;
        creds|socket|source) _filedir ;;
        target|port|code|device-id|fps|bitrate|target-latency-ms|port-range|x11-window-id|x11-window-name) ;;
        pair|test|no-audio|no-video|debug|daemonize|no-cursor|version)
            if [[ $assigned != true ]]; then return 1; fi
            _doubletake_complete_words 'true false'
            ;;
        *) return 1 ;;
    esac
    return 0
}

_doubletake()
{
    # Populated by _init_completion through Bash's dynamic scope.
    # shellcheck disable=SC2034
    local cur prev words cword
    _init_completion -n = || return

    local assigned=false option='' i
    for ((i = 1; i < cword; i++)); do
        case ${words[i]} in
            --) return ;;
            -audio-sink|--audio-sink|-audio-source|--audio-source|-bitrate|--bitrate|-code|--code|\
            -cred-backend|--cred-backend|-creds|--creds|-device-id|--device-id|\
            -fps|--fps|-hwaccel|--hwaccel|-port|--port|-port-range|--port-range|\
            -resolution|--resolution|-s|--s|-socket|--socket|-source|--source|-target|--target|\
            -target-latency-ms|--target-latency-ms|-video-codec|--video-codec|\
            -x11-window-id|--x11-window-id|-x11-window-name|--x11-window-name)
                if ((i + 1 == cword)); then option=${words[i]}; else ((i++)); fi
                ;;
            -*) ;;
            *) return ;;
        esac
    done
    if [[ -z $option && $cur == -*=* ]]; then
        option=${cur%%=*}
        cur=${cur#*=}
        assigned=true
    fi
    option=${option#-}
    option=${option#-}
    _doubletake_complete_value && return
    if [[ $assigned == true ]]; then return; fi

    _doubletake_complete_flags \
        -audio-sink -audio-source -bitrate -code -cred-backend -creds -daemonize -debug \
        -device-id -fps -h -help -hwaccel -no-audio -no-video -no-cursor -pair -port \
        -port-range -resolution -s -socket -source -target -target-latency-ms -test \
        -version -video-codec -x11-window-id -x11-window-name
}

_doubletake_ctl()
{
    # Populated by _init_completion through Bash's dynamic scope.
    # shellcheck disable=SC2034
    local cur prev words cword
    _init_completion -n = || return

    # Go's flag parser stops at the first command. A socket option consumes
    # one argument, including paths which happen to look like command names.
    local i options_done=false option='' assigned=false
    for ((i = 1; i < cword; i++)); do
        if [[ $options_done == true ]]; then
            if [[ ${words[i]} == play ]] && ((i + 1 == cword)); then _filedir; fi
            return
        fi
        case ${words[i]} in
            --) options_done=true ;;
            -socket|--socket)
                if ((i + 1 == cword)); then option=${words[i]}; else ((i++)); fi
                ;;
            -*) ;;
            *)
                if [[ ${words[i]} == play ]] && ((i + 1 == cword)); then _filedir; fi
                return
                ;;
        esac
    done

    if [[ $options_done == false && -z $option && $cur == -*=* ]]; then
        option=${cur%%=*}
        cur=${cur#*=}
        assigned=true
    fi
    option=${option#-}
    option=${option#-}
    case $option in
        socket|version) _doubletake_complete_value && return ;;
    esac
    if [[ $assigned == true ]]; then return; fi

    if [[ $options_done == false && $cur == -* ]]; then
        _doubletake_complete_flags -socket -version -help -h
    else
        _doubletake_complete_words 'status discover devices connect play pin disconnect mute unmute'
    fi
}

complete -F _doubletake doubletake
complete -F _doubletake_ctl doubletake-ctl
