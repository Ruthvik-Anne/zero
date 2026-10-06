#!/bin/sh

set -eu

# Releases are published as GitHub Releases on this repo (no CDN/bucket) —
# see .github/workflows/build-binaries.yml. ZERO_GITHUB_REPO lets a fork
# point this installer at its own releases without editing the script.
zero_repo="${ZERO_GITHUB_REPO:-Ruthvik-Anne/zero}"
# GitHub's release CDN (release-assets.githubusercontent.com, behind a signed
# redirect from github.com/.../releases/download/...) intermittently resets
# the connection mid-download; curl doesn't retry on that by default, gh's
# HTTP client does — this closes the same gap without depending on gh.
zero_curl_retry="--retry 5 --retry-delay 1 --retry-connrefused"
zero_release_channel="${ZERO_RELEASE_CHANNEL:-stable}"
zero_package="${ZERO_PACKAGE:-zero}"
zero_cmd="${ZERO_CMD:-zero}"
zero_esc=$(printf '\033')
zero_original_path="${PATH:-}"
zero_reset="${zero_esc}[0m"
zero_bold="${zero_esc}[1m"
zero_italic="${zero_esc}[3m"
zero_hide_cursor="${zero_esc}[?25l"
zero_show_cursor="${zero_esc}[?25h"
zero_home_cursor="${zero_esc}[H"
zero_clear_screen="${zero_esc}[2J${zero_esc}[H"
zero_clear_line="${zero_esc}[K"
zero_sync_start="${zero_esc}[?2026h"
zero_sync_end="${zero_esc}[?2026l"
zero_color_text="${zero_esc}[38;2;244;244;245m"
zero_color_muted="${zero_esc}[38;2;161;161;170m"
zero_color_dim="${zero_esc}[38;2;113;113;122m"
zero_color_primary="${zero_esc}[38;2;127;91;213m"
zero_color_scan="${zero_esc}[38;2;14;165;233m"
zero_color_warning="${zero_esc}[38;2;245;158;11m"
readonly zero_repo zero_curl_retry zero_release_channel zero_package zero_cmd zero_esc zero_original_path
readonly zero_reset zero_bold zero_italic zero_hide_cursor zero_show_cursor zero_home_cursor zero_clear_screen zero_clear_line
readonly zero_sync_start zero_sync_end
readonly zero_color_text zero_color_muted zero_color_dim zero_color_primary zero_color_scan zero_color_warning

zero_screen_enabled=0
zero_screen_frame=0
zero_screen_cols=80
zero_screen_rows=24
zero_screen_drawn=0
zero_screen_last_cols=0
zero_screen_last_rows=0
zero_screen_layout_ready=0
zero_screen_layout_show_logo=0
zero_screen_layout_lab_width=0
zero_screen_render_lab_width=0
zero_screen_compact=0
zero_download_dir=
zero_lock_dir=
zero_bootstrap_kernel_on_install=0
zero_screen_title=
zero_screen_status=
zero_screen_detail=
zero_screen_question=
zero_animation_frame=0
zero_last_quiet_command_permission_error=0
zero_last_quiet_command_log_path=

main() {
	zero_install_traps
	zero_acquire_install_lock
	zero_init_screen
	if [ "$zero_screen_enabled" = 1 ]; then
		zero_screen "Installing Zero" "" "" ""
	else
		printf '\n\033[1m  Installing Zero\033[0m\n\033[2m  npm global install\033[0m\n\n'
	fi

	start_preflight_checks

	if finish_preflight_checks; then
		check_status=0
	else
		check_status=$?
	fi

	if [ "$check_status" -ne 0 ]; then
		if ! install_node_npm_interactive; then
			exit "$check_status"
		fi

		start_preflight_checks
		if finish_preflight_checks; then
			check_status=0
		else
			check_status=$?
		fi

		if [ "$check_status" -ne 0 ]; then
			exit "$check_status"
		fi
	fi

	resolve_zero_version "$@"
	version="$zero_resolved_version"
	tag="$zero_resolved_tag"

	zero_npm_prefix=$(zero_npm_prefix_lookup)
	installed_version=$(zero_installed_version)
	assert_no_conflicting_zero_install

	if [ "$installed_version" = "$version" ]; then
		printf '\nZero v%s is already installed; nothing to do.\n' "$version"
	else
		confirm_install "$version" "$tag" "$installed_version"
		confirm_kernel_runtime_setup

		download_dir=$(create_temp_dir)
		zero_download_dir="$download_dir"
		tarball_path="$download_dir/$zero_package-$version.tgz"

		download_zero_package "$version" "$tag" "$download_dir"
		install_zero_package "$tarball_path"
		rm -rf "$download_dir"
		zero_download_dir=
	fi

	if [ "${ZERO_NODE_INSTALLED_STANDALONE:-0}" = 1 ]; then
		zero_screen "Zero installed" "" "Checking your shell PATH." ""
		configure_standalone_node_path
	elif command -v "$zero_cmd" >/dev/null 2>&1; then
		if [ "$zero_screen_enabled" = 1 ]; then
			zero_screen "Zero installed" "" "Run it with: $zero_cmd" ""
		else
			printf '\nZero was installed successfully.\n'
			printf '\nRun it with: %s\n' "$zero_cmd"
		fi
	else
		if [ "$zero_screen_enabled" = 1 ]; then
			zero_screen "Zero installed" "" "PATH update needed for $zero_cmd." ""
			zero_restore_terminal
		else
			printf '\nZero was installed successfully.\n'
		fi
		cat <<EOF
The $zero_cmd command was installed, but it is not on your PATH yet.
Check npm's global bin directory with:

  npm bin -g

Then add that directory to your shell PATH.
EOF
	fi
}

create_temp_dir() {
	if command -v mktemp >/dev/null 2>&1; then
		if tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/zero-install.XXXXXX" 2>/dev/null); then
			printf '%s' "$tmp_dir"
			return
		fi
	fi

	printf 'error: mktemp is required to create a secure temporary directory.\n' >&2
	exit 1
}

zero_install_traps() {
	trap 'zero_cleanup' EXIT
	trap 'zero_signal_cleanup 130' INT
	trap 'zero_signal_cleanup 143' TERM
}

zero_acquire_install_lock() {
	zero_lock_dir="${TMPDIR:-/tmp}/zero-install.lock"
	if ! mkdir "$zero_lock_dir" 2>/dev/null; then
		holder=$(cat "$zero_lock_dir/pid" 2>/dev/null || true)
		if [ -n "$holder" ] && kill -0 "$holder" 2>/dev/null; then
			printf 'error: another Zero install or update is already running (pid %s).\n' "$holder" >&2
			exit 1
		fi
		rm -rf "$zero_lock_dir"
		if ! mkdir "$zero_lock_dir" 2>/dev/null; then
			printf 'error: could not acquire the Zero install lock at %s.\n' "$zero_lock_dir" >&2
			exit 1
		fi
	fi
	printf '%s' "$$" >"$zero_lock_dir/pid"
}

zero_release_install_lock() {
	if [ -n "${zero_lock_dir:-}" ] && [ "$(cat "$zero_lock_dir/pid" 2>/dev/null || true)" = "$$" ]; then
		rm -rf "$zero_lock_dir"
	fi
}

zero_cleanup() {
	status=$?
	if [ -n "${zero_download_dir:-}" ] && [ -d "$zero_download_dir" ]; then
		rm -rf "$zero_download_dir"
	fi
	zero_release_install_lock
	zero_restore_terminal
	return "$status"
}

zero_signal_cleanup() {
	zero_restore_terminal
	exit "$1"
}

zero_restore_terminal() {
	if [ "${zero_screen_enabled:-0}" = 1 ]; then
		if ( : <>/dev/tty ) 2>/dev/null; then
			printf '%s%s' "$zero_reset" "$zero_show_cursor" >/dev/tty
		else
			printf '%s%s' "$zero_reset" "$zero_show_cursor" >&2
		fi
	fi
}

zero_init_screen() {
	if [ "${ZERO_INSTALLER_PLAIN:-0}" = 1 ]; then
		return
	fi
	if [ ! -t 1 ]; then
		return
	fi
	if [ "${TERM:-}" = dumb ]; then
		return
	fi
	zero_screen_enabled=1
}

zero_read_terminal_size() {
	zero_screen_cols=80
	zero_screen_rows=24

	if size=$(stty size 2>/dev/null </dev/tty); then
		set -- $size
		if [ "${1:-}" ] && [ "${2:-}" ]; then
			case "$1" in *[!0-9]*|"") ;; *) zero_screen_rows="$1" ;; esac
			case "$2" in *[!0-9]*|"") ;; *) zero_screen_cols="$2" ;; esac
		fi
	fi

	if [ "$zero_screen_cols" -lt 1 ]; then
		zero_screen_cols=80
	fi
	if [ "$zero_screen_rows" -lt 1 ]; then
		zero_screen_rows=24
	fi
}

zero_screen() {
	if [ "$zero_screen_enabled" != 1 ]; then
		return
	fi

	zero_screen_title="${2:-$1}"
	if [ -z "$zero_screen_title" ]; then
		zero_screen_title="$1"
	fi
	zero_screen_status=
	zero_screen_detail="${3:-}"
	zero_screen_question="${4:-}"
	zero_screen_frame=$((zero_screen_frame + 1))
	zero_read_terminal_size
	zero_init_screen_layout
	zero_refresh_screen_layout_mode

	if [ "$zero_screen_drawn" = 0 ] ||
		[ "$zero_screen_cols" -ne "$zero_screen_last_cols" ] ||
		[ "$zero_screen_rows" -ne "$zero_screen_last_rows" ]; then
		zero_screen_prefix="${zero_reset}${zero_clear_screen}${zero_hide_cursor}"
		zero_screen_drawn=1
		zero_screen_last_cols="$zero_screen_cols"
		zero_screen_last_rows="$zero_screen_rows"
	else
		zero_screen_prefix="${zero_reset}${zero_home_cursor}${zero_hide_cursor}"
	fi
	zero_screen_frame_text=$(zero_render_screen)

	if zero_can_write_tty; then
		printf '%s%s%s%s' "$zero_sync_start" "$zero_screen_prefix" "$zero_screen_frame_text" "$zero_sync_end" >/dev/tty
	else
		printf '%s%s%s%s' "$zero_sync_start" "$zero_screen_prefix" "$zero_screen_frame_text" "$zero_sync_end" >&2
	fi
}

zero_can_write_tty() {
	( : <>/dev/tty ) 2>/dev/null
}

zero_init_screen_layout() {
	if [ "$zero_screen_layout_ready" = 1 ]; then
		return
	fi

	zero_screen_layout_ready=1
	zero_screen_layout_show_logo=0
	zero_screen_layout_lab_width=0
	zero_screen_render_lab_width=0
	if zero_terminal_size_supports_logo; then
		zero_screen_layout_show_logo=1
		zero_screen_layout_lab_width=$(zero_lab_width_for_cols "$zero_screen_cols")
	fi
}

zero_refresh_screen_layout_mode() {
	zero_screen_compact=0
	zero_screen_render_lab_width=0
	if [ "$zero_screen_layout_show_logo" != 1 ]; then
		return
	fi
	if [ "$zero_screen_rows" -lt 17 ]; then
		zero_screen_compact=1
		return
	fi

	max_safe_width=$((zero_screen_cols - 1))
	if [ "$max_safe_width" -lt 32 ]; then
		zero_screen_compact=1
		return
	fi

	zero_screen_render_lab_width="$zero_screen_layout_lab_width"
	if [ "$zero_screen_render_lab_width" -gt "$max_safe_width" ]; then
		zero_screen_render_lab_width="$max_safe_width"
	fi
}

zero_terminal_size_supports_logo() {
	[ "$zero_screen_rows" -ge 22 ] && [ "$zero_screen_cols" -ge 42 ]
}

zero_lab_width_for_cols() {
	cols="$1"
	width=$((cols - 6))
	if [ "$width" -gt 78 ]; then
		width=78
	fi
	if [ "$width" -lt 42 ]; then
		width=42
	fi
	max_safe_width=$((cols - 1))
	if [ "$max_safe_width" -lt 1 ]; then
		max_safe_width=1
	fi
	if [ "$width" -gt "$max_safe_width" ]; then
		width="$max_safe_width"
	fi
	if [ "$width" -lt 32 ]; then
		width=32
	fi
	printf '%s' "$width"
}

zero_render_screen() {
	content_height=$(zero_content_height)
	top=$(((zero_screen_rows - content_height) / 2))
	if [ "$top" -lt 0 ]; then
		top=0
	fi

	if zero_show_logo; then
		zero_render_lab
	fi

	y=0
	while [ "$y" -lt "$zero_screen_rows" ]; do
		content_index=$((y - top))
		zero_content_line "$content_index"
		if [ "${zero_content_is_set:-0}" = 1 ]; then
			zero_print_centered_line "$zero_content_text" "$zero_content_width" "$zero_content_style"
		else
			zero_print_centered_line "" 0 ""
		fi
		y=$((y + 1))
	done
}

zero_content_height() {
	height=2
	if zero_show_logo; then
		height=$((height + 15))
	fi
	printf '%s' "$height"
}

zero_show_logo() {
	[ "$zero_screen_layout_show_logo" = 1 ] && [ "$zero_screen_compact" != 1 ] && [ "$zero_screen_render_lab_width" -ge 21 ]
}

zero_content_line() {
	index="$1"
	zero_content_is_set=0
	zero_content_text=
	zero_content_width=0
	zero_content_style=

	if zero_show_logo; then
		case "$index" in
			0|1|2|3|4|5|6|7|8|9|10|11|12|13) zero_set_lab_line "$index" ;;
			14) zero_set_blank_line ;;
		esac
		if [ "$zero_content_is_set" = 1 ]; then
			return
		fi
		index=$((index - 15))
	fi

	if [ "$index" -lt 0 ]; then
		return
	fi

	if [ "$index" -eq 0 ]; then
		if [ -n "$zero_screen_question" ]; then
			zero_set_text_line "$(zero_screen_primary_text)" "$zero_bold$zero_color_text"
		else
			zero_set_title_line "$zero_screen_title"
		fi
		return
	fi

	if [ "$index" -eq 1 ]; then
		if [ -n "$zero_screen_question" ]; then
			zero_set_text_line "Press Enter to continue; type n to cancel." "$zero_color_muted"
		elif [ -n "$zero_screen_detail" ]; then
			zero_set_text_line "$zero_screen_detail" "$zero_color_muted"
		else
			zero_set_blank_line
		fi
		return
	fi
}

zero_screen_primary_text() {
	if [ -z "$zero_screen_question" ]; then
		printf '%s' "$zero_screen_title"
		return
	fi

	case "$zero_screen_question" in
		*'[Y/n]'*) printf '%s [Y/n] >' "$zero_screen_title" ;;
		*) printf '%s %s' "$zero_screen_title" "$zero_screen_question" ;;
	esac
}

zero_set_lab_line() {
	lab_row="$1"
	eval "zero_lab_text=\${zero_lab_row_$lab_row:-}"
	zero_content_is_set=1
	zero_content_text="$zero_lab_text"
	zero_content_width="$zero_screen_render_lab_width"
	zero_content_style=
}

# One awk pass renders the whole lab field for the current frame and size.
# The field is sampled in square units (cells are about twice as tall as wide),
# so its shape stays the same at any terminal width or height.
zero_lab_program='
BEGIN {
	logo[2] = "     ▄▄████████▄▄"
	logo[3] = "   ▄██▀▀      ▀▀██▄"
	logo[4] = "  ██▀            ▀██"
	logo[5] = " ██                ██"
	logo[6] = logo[5]
	logo[7] = logo[5]
	logo[8] = logo[5]
	logo[9] = "  ██▄            ▄██"
	logo[10] = "   ▀██▄▄      ▄▄██▀"
	logo[11] = "     ▀▀████████▀▀"
	cx = W / 2
	cy = H / 2
	unit = (W / 2 < H) ? W / 2 : H
	t = frame * 0.42
	ls = int((W - 21) / 2)
	le = ls + 21
	horizon = int(H * 0.58)
	for (y = 0; y < H; y++) {
		line = ""
		active = ""
		x = 0
		while (x < W) {
			if (LOGO && y >= 2 && y <= 11 && x == ls) {
				if (active != "") line = line RESET
				active = ""
				line = line C_TEXT logo[y] RESET
				x = le
				continue
			}
			nx = (x + 0.5 - cx) / unit
			ny = 2 * (y + 0.5 - cy) / unit
			f = sin(3.1 * nx + t) + cos(2.4 * ny - 0.7 * t) + sin(1.7 * (nx + ny) + 0.4 * t)
			g = sin(5.3 * nx * ny + 0.9 * t)
			v = (f + g) / 4
			a = v < 0 ? -v : v
			ch = " "
			st = ""
			hash = (x * 37 + y * 53 + frame * 11 + x * y * 3) % 101
			if (a < 0.12) {
				if (hash < 3) { ch = "·"; st = C_DIM }
			} else if (a < 0.5) {
				ch = (int(a * 14) % 2) ? "╌" : "·"
				st = C_DIM
			} else if (a < 0.78) {
				ch = ((x + y) % 2) ? "╎" : "┃"
				st = C_SCAN
			} else {
				if ((x + frame) % 9 == 0) { ch = "◆"; st = C_WARN } else { ch = "•"; st = C_PRIMARY }
			}
			if (y == horizon && x % 2 == 0 && (x + frame) % 13 < 2) {
				ch = "─"
				st = (x > W * 0.6) ? C_PRIMARY : C_DIM
			}
			if (st != active) {
				if (active != "") line = line RESET
				if (st != "") line = line st
				active = st
			}
			line = line ch
			x++
		}
		if (active != "") line = line RESET
		print line
	}
}'

zero_render_lab() {
	lab_index=0
	while [ "$lab_index" -lt 14 ]; do
		eval "zero_lab_row_$lab_index="
		lab_index=$((lab_index + 1))
	done

	zero_lab_rows=$(awk -v W="$zero_screen_render_lab_width" -v H=14 -v frame="$zero_screen_frame" -v LOGO=1 \
		-v C_TEXT="$zero_color_text" -v C_DIM="$zero_color_dim" -v C_PRIMARY="$zero_color_primary" \
		-v C_SCAN="$zero_color_scan" -v C_WARN="$zero_color_warning" -v RESET="$zero_reset" \
		"$zero_lab_program" 2>/dev/null) || return 0

	lab_index=0
	while IFS= read -r lab_line; do
		eval "zero_lab_row_$lab_index=\$lab_line"
		lab_index=$((lab_index + 1))
	done <<EOF
$zero_lab_rows
EOF
}

zero_set_blank_line() {
	zero_content_is_set=1
	zero_content_text=
	zero_content_width=0
	zero_content_style=
}

zero_set_text_line() {
	max_width=$((zero_screen_cols - 4))
	if [ "$max_width" -lt 1 ]; then
		max_width=1
	fi
	zero_content_text=$(zero_fit_ascii "$1" "$max_width")
	zero_content_width=${#zero_content_text}
	zero_content_style="$2"
	zero_content_is_set=1
}

zero_set_title_line() {
	max_width=$((zero_screen_cols - 4))
	if [ "$max_width" -lt 1 ]; then
		max_width=1
	fi
	zero_content_text=$(zero_fit_ascii "$1" "$max_width")
	zero_content_width=${#zero_content_text}
	case "$zero_content_text" in
		*"Zero"*)
			zero_content_text=$(zero_style_zero_title "$zero_content_text")
			zero_content_style=
			;;
		*)
			zero_content_style="$zero_bold$zero_color_primary"
			;;
	esac
	zero_content_is_set=1
}

zero_style_zero_title() {
	text="$1"
	styled=
	while :; do
		case "$text" in
			*"Zero"*)
				before=${text%%Zero*}
				rest=${text#*Zero}
				styled="${styled}${zero_bold}${zero_color_primary}${before}"
				styled="${styled}${zero_bold}${zero_color_primary}Zero${zero_reset}"
				text="$rest"
				;;
			*)
				styled="${styled}${zero_bold}${zero_color_primary}${text}${zero_reset}"
				printf '%s' "$styled"
				return
				;;
		esac
	done
}

zero_fit_ascii() {
	text="$1"
	max_width="$2"
	if [ "${#text}" -le "$max_width" ]; then
		printf '%s' "$text"
		return
	fi
	if [ "$max_width" -le 3 ]; then
		printf '%s' "$text" | cut -c 1-"$max_width"
		return
	fi
	cut_width=$((max_width - 3))
	printf '%s...' "$(printf '%s' "$text" | cut -c 1-"$cut_width")"
}

zero_print_centered_line() {
	text="$1"
	width="$2"
	style="$3"
	left=$(((zero_screen_cols - width) / 2))
	if [ "$left" -lt 0 ]; then
		left=0
	fi
	if [ -n "$style" ]; then
		printf '%*s%s%s%s%s\n' "$left" "" "$style" "$text" "$zero_reset" "$zero_clear_line"
	else
		printf '%*s%s%s\n' "$left" "" "$text" "$zero_clear_line"
	fi
}

zero_place_prompt_cursor() {
	max_width=$((zero_screen_cols - 4))
	if [ "$max_width" -lt 1 ]; then
		max_width=1
	fi
	prompt_text=$(zero_fit_ascii "$(zero_screen_primary_text)" "$max_width")
	prompt_width=${#prompt_text}
	content_height=$(zero_content_height)
	top=$(((zero_screen_rows - content_height) / 2))
	if [ "$top" -lt 0 ]; then
		top=0
	fi
	prompt_index=0
	if zero_show_logo; then
		prompt_index=$((prompt_index + 15))
	fi
	row=$((top + prompt_index + 1))
	col=$(((zero_screen_cols - prompt_width) / 2 + prompt_width + 2))
	if [ "$col" -lt 1 ]; then
		col=1
	fi
	if [ "$col" -gt "$zero_screen_cols" ]; then
		col="$zero_screen_cols"
	fi
	if ( : <>/dev/tty ) 2>/dev/null; then
		printf '%s%s%s[%s;%sH' "$zero_reset" "$zero_show_cursor" "$zero_esc" "$row" "$col" >/dev/tty
	else
		printf '%s%s%s[%s;%sH' "$zero_reset" "$zero_show_cursor" "$zero_esc" "$row" "$col" >&2
	fi
}

zero_pulse() {
	case $((zero_screen_frame % 4)) in
		0) printf '.' ;;
		1) printf '..' ;;
		2) printf '...' ;;
		*) printf '' ;;
	esac
}

zero_animation_detail_count() {
	details="$1"
	case "$details" in
		*'
'*) printf '%s\n' "$details" | wc -l | tr -d ' ' ;;
		*) printf '1' ;;
	esac
}

zero_animation_current_frame() {
	frame="${zero_animation_frame:-1}"
	case "$frame" in
		""|*[!0-9]*) frame=1 ;;
	esac
	if [ "$frame" -lt 1 ]; then
		frame=1
	fi
	printf '%s' "$frame"
}

zero_animation_step_index() {
	details="$1"
	detail_count=$(zero_animation_detail_count "$details")
	frame=$(zero_animation_current_frame)
	detail_index=$(((frame - 1) / 24 + 1))
	if [ "$detail_index" -gt "$detail_count" ]; then
		detail_index="$detail_count"
	fi
	printf '%s' "$detail_index"
}

zero_static_progress_title() {
	case "$1" in
		*...) printf '%s' "$1" ;;
		*) printf '%s...' "$1" ;;
	esac
}

zero_animation_status() {
	status="$1"
	details="$2"
	status_mode="$3"
	case "$status_mode" in
		static) zero_static_progress_title "$status" ;;
		*) printf '%s%s' "$status" "$(zero_pulse)" ;;
	esac
}

zero_animation_detail() {
	details="$1"
	case "$details" in
		*'
'*)
			detail_index=$(zero_animation_step_index "$details")
			printf '%s\n' "$details" | sed -n "${detail_index}p"
			;;
		*) printf '%s' "$details" ;;
	esac
}

zero_run_quiet_with_animation() {
	title="$1"
	status="$2"
	detail="$3"
	shift 3

	zero_run_quiet_with_animation_command "$title" "$status" "$detail" pulse 0 "$@"
}

zero_run_quiet_with_animation_steps() {
	title="$1"
	status="$2"
	details="$3"
	shift 3

	zero_run_quiet_with_animation_command "$title" "$status" "$details" static 0 "$@"
}

zero_run_quiet_with_animation_command() {
	title="$1"
	status="$2"
	details="$3"
	status_mode="$4"
	suppress_error_display="${5:-0}"
	shift 5

	if [ "$zero_screen_enabled" != 1 ]; then
		printf '%s\n' "$status" >&2
		zero_last_quiet_command_permission_error=0
		"$@"
		return
	fi

	output_dir=$(create_temp_dir)
	output_file="$output_dir/output"
	"$@" >"$output_file" 2>&1 &
	command_pid=$!
	zero_animation_frame=0

	while kill -0 "$command_pid" 2>/dev/null; do
		zero_animation_frame=$((zero_animation_frame + 1))
		status_display=$(zero_animation_status "$status" "$details" "$status_mode")
		zero_screen "$title" "$status_display" "$(zero_animation_detail "$details")" ""
		sleep 0.18
	done

	if wait "$command_pid"; then
		command_status=0
	else
		command_status=$?
	fi

	zero_last_quiet_command_permission_error=0
	zero_last_quiet_command_log_path=
	if [ "$command_status" -ne 0 ] && [ -s "$output_file" ]; then
		if grep -qiE 'EACCES|permission denied' "$output_file"; then
			zero_last_quiet_command_permission_error=1
		fi
		if [ "$suppress_error_display" = 1 ]; then
			# Technical users can still ask to see this; a first-time user never
			# needs npm's raw stack trace on screen.
			zero_last_quiet_command_log_path="${TMPDIR:-/tmp}/zero-install-error.log"
			cp "$output_file" "$zero_last_quiet_command_log_path" 2>/dev/null || zero_last_quiet_command_log_path=
		else
			zero_restore_terminal
			printf '\n' >&2
			cat "$output_file" >&2
		fi
	fi
	rm -rf "$output_dir"
	return "$command_status"
}

zero_prompt_yes_no() {
	question="$1"
	detail="$2"
	input_prompt="$3"

	if ( : <>/dev/tty ) 2>/dev/null; then
		prompt_input=tty
		exec 3<>/dev/tty
	elif [ -t 0 ]; then
		prompt_input=stdin
	else
		return 2
	fi

	if [ "$zero_screen_enabled" = 1 ]; then
		zero_screen "$question" "" "$detail" "$input_prompt"
		zero_place_prompt_cursor "$input_prompt"
	else
		printf '%s\n' "$detail"
		if [ "$prompt_input" = tty ]; then
			printf '%s ' "$input_prompt" >&3
		else
			printf '%s ' "$input_prompt" >&2
		fi
	fi

	if [ "$prompt_input" = tty ]; then
		if ! IFS= read -r answer <&3; then
			answer=
		fi
		exec 3>&-
	else
		if ! IFS= read -r answer; then
			answer=
		fi
	fi

	case "$answer" in
		n|N|no|NO)
			return 1
			;;
	esac
	return 0
}

start_preflight_checks() {
	preflight_dir=$(create_temp_dir)
	preflight_file="$preflight_dir/preflight"
	run_preflight_checks >"$preflight_file" &
	preflight_pid=$!
}

finish_preflight_checks() {
	if [ "$zero_screen_enabled" = 1 ]; then
		while kill -0 "$preflight_pid" 2>/dev/null; do
			zero_screen "Checking Node.js and npm$(zero_pulse)" "" "" ""
			sleep 0.18
		done
	fi

	if wait "$preflight_pid"; then
		preflight_status=0
	else
		preflight_status=$?
	fi

	if [ "$zero_screen_enabled" = 1 ]; then
		if [ "$preflight_status" -ne 0 ]; then
			preflight_summary=$(sed -n '1p' "$preflight_file")
			zero_screen "Node.js 20.6.0 or newer is required" "" "$preflight_summary" ""
			sleep 0.4
		elif [ -s "$preflight_file" ]; then
			preflight_summary="Existing $zero_cmd command found on PATH."
			zero_screen "Environment ready" "" "$preflight_summary" ""
			sleep 0.4
		fi
	else
		cat "$preflight_file"
	fi
	rm -rf "$preflight_dir"
	return "$preflight_status"
}

run_preflight_checks() {
	status=0
	yellow="${zero_esc}[33m"
	reset="${zero_esc}[0m"

	if command -v node >/dev/null 2>&1; then
		node_version=$(node --version)
		if ! node -e 'const [major, minor, patch] = process.versions.node.split(".").map(Number); process.exit(major > 20 || (major === 20 && (minor > 6 || (minor === 6 && patch >= 0))) ? 0 : 1)' >/dev/null; then
			printf 'error: Zero requires Node.js 20.6.0 or newer. Found %s.\n' "$node_version"
			status=1
		fi
	else
		printf 'error: Node.js 20.6.0 or newer is required to install Zero.\n'
		status=1
	fi

	if ! command -v npm >/dev/null 2>&1; then
		printf 'error: npm is required to install Zero.\n'
		status=1
	fi

	if [ "$status" -ne 0 ]; then
		printf '\n'
	fi

	if zero_path=$(command -v "$zero_cmd" 2>/dev/null); then
		printf '%sExisting %s found at: %s%s\n' "$yellow" "$zero_cmd" "$zero_path" "$reset"
		printf '\n'
	fi

	return "$status"
}

# Sets zero_resolved_version and zero_resolved_tag; doesn't return via stdout
# since it needs to hand back two values.
resolve_zero_version() {
	if [ "${1:-}" ]; then
		case "$1" in
			stable|beta) release_channel="$1" ;;
			*)
				zero_resolved_version="$(normalize_version "$1")"
				zero_resolved_tag="v$zero_resolved_version"
				return
				;;
		esac
	else
		release_channel="$zero_release_channel"
	fi

	if [ "${ZERO_VERSION:-}" ]; then
		zero_resolved_version="$(normalize_version "$ZERO_VERSION")"
		zero_resolved_tag="v$zero_resolved_version"
		return
	fi

	case "$release_channel" in
		stable|beta) ;;
		*)
			printf 'error: invalid Zero release channel: %s\n' "$release_channel" >&2
			exit 1
			;;
	esac

	# zero_run_quiet_with_animation discards the wrapped command's stdout
	# (only shown on failure) when the animated screen is active, so the
	# resolved value has to come back through a file, not $(...).
	resolve_dir=$(create_temp_dir)
	resolved_path="$resolve_dir/resolved"

	# The beta release's own git tag is always the literal "beta" (a floating
	# tag the release workflow force-moves on every main build); the real
	# beta version only shows up in its asset filenames, so resolving it
	# needs a different query than resolving the stable channel's tag.
	if [ "$release_channel" = beta ]; then
		zero_run_quiet_with_animation \
			"Resolving latest release" \
			"Resolving latest release" \
			"Checking the beta release channel." \
			zero_write_resolved_beta_version "$resolved_path"
		resolved_version="$(tr -d '[:space:]' <"$resolved_path" 2>/dev/null || true)"
		resolved_tag=beta
	else
		zero_run_quiet_with_animation \
			"Resolving latest release" \
			"Resolving latest release" \
			"Checking the stable release channel." \
			zero_write_resolved_stable_tag "$resolved_path"
		resolved_tag="$(tr -d '[:space:]' <"$resolved_path" 2>/dev/null || true)"
		resolved_version="${resolved_tag#v}"
	fi
	rm -rf "$resolve_dir"

	if [ -z "$resolved_version" ] || [ -z "$resolved_tag" ]; then
		printf 'error: could not resolve the latest Zero release from %s\n' "$zero_repo" >&2
		exit 1
	fi

	zero_resolved_tag="$resolved_tag"
	zero_resolved_version="$(normalize_version "$resolved_version")"
}

zero_write_resolved_stable_tag() {
	zero_resolve_stable_tag >"$1"
}

zero_write_resolved_beta_version() {
	zero_resolve_beta_version >"$1"
}

# Prints the stable channel's current release tag (e.g. v0.7.3) via the
# public, unauthenticated GitHub REST API.
zero_resolve_stable_tag() {
	if ! command -v curl >/dev/null 2>&1; then
		printf 'error: curl is required to resolve the latest Zero version.\n' >&2
		exit 1
	fi

	curl -fsSL $zero_curl_retry -H "Accept: application/vnd.github+json" \
		"https://api.github.com/repos/$zero_repo/releases/latest" 2>/dev/null |
		sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1
}

# Prints the version embedded in the beta release's main-package tarball
# name (e.g. zero-0.7.3-beta.5.abc1234.tgz -> 0.7.3-beta.5.abc1234). The
# version starts with a digit, which is what distinguishes it from the
# zero-ai/zero-core/zero-tui companion tarballs in the same release.
zero_resolve_beta_version() {
	if ! command -v curl >/dev/null 2>&1; then
		printf 'error: curl is required to resolve the latest Zero version.\n' >&2
		exit 1
	fi

	asset_name=$(curl -fsSL $zero_curl_retry -H "Accept: application/vnd.github+json" \
		"https://api.github.com/repos/$zero_repo/releases/tags/beta" 2>/dev/null |
		grep -oE "\"${zero_package}-[0-9][^\"]*\.tgz\"" | head -n1 | tr -d '"')

	if [ -n "$asset_name" ]; then
		version="${asset_name#"${zero_package}"-}"
		printf '%s' "${version%.tgz}"
	fi
}

normalize_version() {
	version="${1#v}"
	case "$version" in
		"")
			printf 'error: empty Zero version.\n' >&2
			exit 1
			;;
		*[!0-9A-Za-z.-]*)
			printf 'error: invalid Zero version: %s\n' "$1" >&2
			exit 1
			;;
	esac
	printf '%s' "$version"
}

install_node_npm_interactive() {
	method=$(detect_node_install_method)
	case "$method" in
		homebrew) label="Homebrew" ;;
		apt) label="apt" ;;
		apk) label="apk" ;;
		standalone) label="standalone Node.js" ;;
		*)
			method=standalone
			label="standalone Node.js"
			;;
	esac

	if zero_prompt_yes_no \
		"Install Node.js and npm with $label?" \
		"Required before Zero can be installed." \
		"Install? [Y/n]"; then
		install_node_npm "$method" "$label"
		return
	else
		prompt_status=$?
	fi
	if [ "$prompt_status" -eq 2 ]; then
		printf 'No terminal detected; install Node.js 20.6.0 or newer and npm, then run this installer again.\n'
	else
		printf '\nInstall Node.js 20.6.0 or newer and npm, then run this installer again.\n'
	fi
	return 1
}

detect_node_install_method() {
	case "$(uname -s)" in
		Darwin)
			if command -v brew >/dev/null 2>&1; then
				printf 'homebrew'
			else
				printf 'standalone'
			fi
			;;
		Linux)
			if command -v apt-cache >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1 && apt_node_candidate_is_new_enough; then
				printf 'apt'
			elif command -v apk >/dev/null 2>&1 && apk_node_candidate_is_new_enough; then
				printf 'apk'
			else
				printf 'standalone'
			fi
			;;
		*)
			printf 'standalone'
			;;
	esac
}

apt_node_candidate_is_new_enough() {
	version=$(apt-cache policy nodejs 2>/dev/null | awk '/Candidate:/ { print $2; exit }')
	[ -n "$version" ] && [ "$version" != "(none)" ] && node_version_string_is_new_enough "$version"
}

apk_node_candidate_is_new_enough() {
	version=$(apk search -x nodejs 2>/dev/null | awk -F- '/^nodejs-/ { print $2; exit }')
	[ -n "$version" ] && node_version_string_is_new_enough "$version"
}

node_version_string_is_new_enough() {
	version="${1#v}"
	case "$version" in
		[0-9]*) ;;
		*) return 1 ;;
	esac
	version="${version%%[!0-9.]*}"
	version_ifs=${IFS- }
	IFS=.
	set -- $version
	IFS=$version_ifs
	major="${1:-}"
	minor="${2:-0}"
	patch="${3:-0}"
	case "$major" in ''|*[!0-9]*) return 1 ;; esac
	case "$minor" in ''|*[!0-9]*) minor=0 ;; esac
	case "$patch" in ''|*[!0-9]*) patch=0 ;; esac

	[ "$major" -gt 20 ] && return 0
	[ "$major" -eq 20 ] && [ "$minor" -gt 6 ] && return 0
	[ "$major" -eq 20 ] && [ "$minor" -eq 6 ] && [ "$patch" -ge 0 ] && return 0
	return 1
}

install_node_npm() {
	method="$1"
	label="$2"

	if [ "$zero_screen_enabled" != 1 ]; then
		printf '\nInstalling Node.js and npm with %s...\n\n' "$label"
		run_node_install_method "$method"
	else
		prepare_sudo_for_node_install "$method"
		node_install_details="Using $label.
Resolving Node.js packages.
Downloading Node.js runtime.
Installing npm.
Preparing Zero setup."
		zero_run_quiet_with_animation_steps \
			"Installing Node.js and npm" \
			"Installing Node.js and npm" \
			"$node_install_details" \
			run_node_install_method "$method"
	fi

	if [ "$method" = standalone ]; then
		load_standalone_node
		ZERO_NODE_INSTALLED_STANDALONE=1
	fi
	hash -r
	if [ "$zero_screen_enabled" = 1 ]; then
		zero_screen "Node.js and npm installed" "" "Continuing Zero setup." ""
	else
		printf '\nNode.js and npm are installed.\n\n'
	fi
}

node_install_needs_sudo() {
	if [ "${EUID:-$(id -u)}" -eq 0 ]; then
		return 1
	fi

	case "$1" in
		apt|apk)
			return 0
			;;
		standalone)
			[ "$(uname -s)" = Linux ] || return 1
			command -v xz >/dev/null 2>&1 && return 1
			command -v apt-get >/dev/null 2>&1 || command -v apk >/dev/null 2>&1
			;;
		*)
			return 1
			;;
	esac
}

zero_has_sudo() {
	command -v sudo >/dev/null 2>&1
}

zero_has_su() {
	command -v su >/dev/null 2>&1
}

# No sudo and no su: there is no privilege-escalation mechanism to request through,
# so fail with actionable guidance instead of a raw "sudo: command not found".
zero_no_privilege_escalation() {
	printf 'error: root access is required for %s, but neither sudo nor su is available.\n' "$1" >&2
	printf 'Install sudo, or run this installer as root, then run it again.\n' >&2
	return 1
}

prepare_sudo_for_node_install() {
	method="$1"
	if ! node_install_needs_sudo "$method"; then
		return 0
	fi

	if zero_has_sudo; then
		zero_screen "Preparing Node.js install" "" "This may ask for your sudo password." ""
		zero_restore_terminal
		printf '\n'
		sudo -v
	elif zero_has_su; then
		zero_screen "Preparing Node.js install" "" "sudo is not installed; this may ask for the root password instead." ""
		zero_restore_terminal
		printf '\n'
		su -c true
	else
		zero_restore_terminal
		zero_no_privilege_escalation "installing Node.js with $method"
	fi
}

run_node_install_method() {
	case "$1" in
		homebrew) install_node_with_homebrew ;;
		apt) install_node_with_apt ;;
		apk) install_node_with_apk ;;
		standalone) install_node_standalone ;;
	esac
}

install_node_with_homebrew() {
	if brew list node >/dev/null 2>&1; then
		brew upgrade node
	else
		brew install node
	fi
}

install_node_with_apt() {
	print_sudo_note
	if [ "${EUID:-$(id -u)}" -eq 0 ]; then
		apt-get update
		apt-get install -y nodejs npm
	else
		run_with_sudo sh -c 'apt-get update && apt-get install -y nodejs npm'
	fi
}

install_node_with_apk() {
	print_sudo_note
	run_with_sudo apk add --update-cache nodejs npm
}

install_node_standalone() {
	node_platform=$(detect_node_binary_platform) || {
		printf 'Unsupported operating system for automatic Node.js install: %s\n' "$(uname -s)"
		return 1
	}
	node_arch=$(detect_node_binary_arch) || {
		printf 'Unsupported CPU architecture for automatic Node.js install: %s\n' "$(uname -m)"
		return 1
	}
	node_dist_base="https://nodejs.org/dist/latest-v22.x"
	node_base_dir=$(node_standalone_base_dir)
	node_tmp_dir=$(create_temp_dir)

	mkdir -p "$node_tmp_dir" "$node_base_dir"

	printf 'Resolving Node.js binary for %s-%s\n' "$node_platform" "$node_arch"
	curl -fsSL $zero_curl_retry "$node_dist_base/SHASUMS256.txt" -o "$node_tmp_dir/SHASUMS256.txt"
	node_file=$(awk -v suffix="-$node_platform-$node_arch.tar.xz" '
		index($2, "node-v") == 1 && length($2) >= length(suffix) && substr($2, length($2) - length(suffix) + 1) == suffix { print $2; exit }
	' "$node_tmp_dir/SHASUMS256.txt")
	if [ -z "$node_file" ]; then
		printf 'No Node.js binary is available for %s-%s.\n' "$node_platform" "$node_arch"
		rm -rf "$node_tmp_dir"
		return 1
	fi
	case "$node_file" in
		*/*|*\\*|*..*)
			printf 'Unsafe Node.js archive name in checksum manifest: %s\n' "$node_file"
			rm -rf "$node_tmp_dir"
			return 1
			;;
		node-v*-"$node_platform"-"$node_arch".tar.xz) ;;
		*)
			printf 'Unexpected Node.js archive name in checksum manifest: %s\n' "$node_file"
			rm -rf "$node_tmp_dir"
			return 1
			;;
	esac

	printf 'Downloading Node.js %s\n' "${node_file%.tar.xz}"
	curl -fsSL $zero_curl_retry "$node_dist_base/$node_file" -o "$node_tmp_dir/$node_file"
	verify_node_standalone_download "$node_tmp_dir" "$node_file"
	ensure_node_standalone_extract_tools "$node_platform"

	node_dir="$node_base_dir/${node_file%.tar.xz}"
	rm -rf "$node_dir"
	printf 'Extracting Node.js to %s\n' "$node_dir"
	tar -xf "$node_tmp_dir/$node_file" -C "$node_base_dir"
	rm -f "$node_base_dir/current"
	ln -s "$node_dir" "$node_base_dir/current"
	rm -rf "$node_tmp_dir"
	printf 'Node.js installed at %s\n' "$node_dir"
}

verify_node_standalone_download() {
	checksum_dir="$1"
	checksum_file_name="$2"
	awk -v file="$checksum_file_name" '$2 == file { print }' "$checksum_dir/SHASUMS256.txt" >"$checksum_dir/SHASUMS256.selected"

	if command -v sha256sum >/dev/null 2>&1; then
		printf 'Verifying Node.js download\n'
		(cd "$checksum_dir" && sha256sum -c SHASUMS256.selected)
	elif command -v shasum >/dev/null 2>&1; then
		printf 'Verifying Node.js download\n'
		(cd "$checksum_dir" && shasum -a 256 -c SHASUMS256.selected)
	else
		printf 'error: sha256sum or shasum is required to verify the Node.js download.\n'
		return 1
	fi
}

ensure_node_standalone_extract_tools() {
	extract_platform="$1"

	if [ "$extract_platform" = linux ] && ! command -v xz >/dev/null 2>&1; then
		printf 'Installing xz-utils for Node.js archive extraction\n'
		print_sudo_note
		if command -v apt-get >/dev/null 2>&1; then
			run_with_sudo apt-get update
			run_with_sudo apt-get install -y xz-utils
		elif command -v apk >/dev/null 2>&1; then
			run_with_sudo apk add --update-cache xz
		else
			printf 'xz is required to extract Node.js. Install xz and run this installer again.\n'
			return 1
		fi
	fi
}

load_standalone_node() {
	ZERO_STANDALONE_NODE_BIN="$(node_standalone_base_dir)/current/bin"
	PATH="$ZERO_STANDALONE_NODE_BIN:$PATH"
	export ZERO_STANDALONE_NODE_BIN PATH
}

node_standalone_base_dir() {
	if [ -n "${XDG_DATA_HOME:-}" ]; then
		printf '%s/zero-node' "$XDG_DATA_HOME"
	else
		printf '%s/.local/share/zero-node' "$HOME"
	fi
}

detect_node_binary_platform() {
	case "$(uname -s)" in
		Darwin) printf 'darwin' ;;
		Linux) printf 'linux' ;;
		*) return 1 ;;
	esac
}

detect_node_binary_arch() {
	case "$(uname -m)" in
		x86_64|amd64) printf 'x64' ;;
		arm64|aarch64) printf 'arm64' ;;
		armv7l) printf 'armv7l' ;;
		ppc64le) printf 'ppc64le' ;;
		s390x) printf 's390x' ;;
		*) return 1 ;;
	esac
}

print_sudo_note() {
	if [ "${EUID:-$(id -u)}" -eq 0 ]; then
		return
	fi
	if zero_has_sudo; then
		printf 'This may ask for your sudo password.\n\n'
	elif zero_has_su; then
		printf 'sudo is not installed; this may ask for the root password instead.\n\n'
	fi
}

run_with_sudo() {
	if [ "${EUID:-$(id -u)}" -eq 0 ]; then
		"$@"
	elif zero_has_sudo; then
		sudo "$@"
	elif zero_has_su; then
		run_with_su "$@"
	else
		zero_no_privilege_escalation "$*"
	fi
}

# su -c takes one shell command string, not an argv array, so each argument
# must be quoted individually before joining (matches the existing
# zero_shell_quote convention used for shell-profile commands below).
run_with_su() {
	command_string=""
	for arg in "$@"; do
		command_string="$command_string $(zero_shell_quote "$arg")"
	done
	su -c "${command_string# }"
}

configure_standalone_node_path() {
	if original_zero_path=$(resolve_zero_with_original_path); then
		case "$original_zero_path" in
			"$ZERO_STANDALONE_NODE_BIN/"*)
				if [ "$zero_screen_enabled" = 1 ]; then
					zero_screen "Zero installed" "" "Run it with: $zero_cmd" ""
				else
					printf '\nRun it with: %s\n' "$zero_cmd"
				fi
				return 0
				;;
		esac
		if [ "$zero_screen_enabled" = 1 ]; then
			zero_screen "Zero installed" "" "PATH update needed for $zero_cmd." ""
		else
			printf '%s was installed, but your shell is not using that install yet.\n' "$zero_cmd"
			printf 'Your shell currently resolves %s to: %s\n' "$zero_cmd" "$original_zero_path"
		fi
	else
		if [ "$zero_screen_enabled" = 1 ]; then
			zero_screen "Zero installed" "" "PATH update needed for $zero_cmd." ""
		else
			printf '%s was installed, but your shell is not using that install yet.\n' "$zero_cmd"
		fi
	fi

	profile=$(detect_shell_profile) || {
		if [ "$zero_screen_enabled" = 1 ]; then
			zero_restore_terminal
			printf '\n'
		fi
		print_standalone_path_manual_instructions
		return 0
	}

	if shell_profile_has_standalone_node_path "$profile"; then
		if [ "$zero_screen_enabled" = 1 ]; then
			zero_screen "Zero installed" "" "Run: $(zero_source_profile_command "$profile")" ""
		else
			printf '%s already contains %s.\n' "$profile" "$ZERO_STANDALONE_NODE_BIN"
			printf 'Restart your shell or run: %s\n' "$(zero_source_profile_command "$profile")"
		fi
		return 0
	fi

	prompt_add_standalone_node_path "$profile"
}

resolve_zero_with_original_path() {
	saved_path=$PATH
	PATH=$zero_original_path
	if command -v "$zero_cmd" 2>/dev/null; then
		status=0
	else
		status=$?
	fi
	PATH=$saved_path
	return "$status"
}

detect_shell_profile() {
	if [ -n "${ZERO_SHELL_PROFILE:-}" ]; then
		printf '%s' "$ZERO_SHELL_PROFILE"
		return 0
	fi
	if [ -z "${HOME:-}" ]; then
		return 1
	fi

	shell_name="${SHELL:-}"
	shell_name="${shell_name##*/}"
	case "$shell_name" in
		zsh)
			printf '%s/.zshrc' "${ZDOTDIR:-$HOME}"
			;;
		bash)
			printf '%s/.bashrc' "$HOME"
			;;
		*)
			if [ -f "$HOME/.zshrc" ]; then
				printf '%s/.zshrc' "$HOME"
			elif [ -f "$HOME/.bashrc" ]; then
				printf '%s/.bashrc' "$HOME"
			else
				printf '%s/.profile' "$HOME"
			fi
			;;
	esac
}

shell_profile_has_standalone_node_path() {
	profile="$1"
	[ -f "$profile" ] && grep -F "$ZERO_STANDALONE_NODE_BIN" "$profile" >/dev/null 2>&1
}

prompt_add_standalone_node_path() {
	profile="$1"
	path_line=$(standalone_node_path_line)

	if ! zero_prompt_yes_no \
		"Add standalone Node.js to your PATH?" \
		"Updates $profile so future shells can run $zero_cmd." \
		"Update PATH? [Y/n]"; then
		if [ "$zero_screen_enabled" = 1 ]; then
			zero_restore_terminal
			printf '\n'
		fi
		print_standalone_path_manual_instructions
		return 0
	fi

	mkdir -p "$(dirname "$profile")"
	{
		printf '\n# Zero standalone Node.js\n'
		printf '%s\n' "$path_line"
	} >>"$profile"
	if [ "$zero_screen_enabled" = 1 ]; then
		zero_screen "Zero installed" "" "Run: $(zero_source_profile_command "$profile")" ""
	else
		printf 'Added %s to %s.\n' "$ZERO_STANDALONE_NODE_BIN" "$profile"
		printf 'Restart your shell or run: %s\n' "$(zero_source_profile_command "$profile")"
	fi
}

print_standalone_path_manual_instructions() {
	printf 'Add this to your shell profile to use %s from new shells:\n\n' "$zero_cmd"
	printf '  %s\n' "$(standalone_node_path_line)"
	printf '\nThen restart your shell and run: %s\n' "$zero_cmd"
}

standalone_node_path_line() {
	printf 'export PATH="%s:$PATH"' "$ZERO_STANDALONE_NODE_BIN"
}

zero_shell_quote() {
	quoted=$(printf '%s' "$1" | sed "s/'/'\\\\''/g")
	printf "'%s'" "$quoted"
}

zero_source_profile_command() {
	printf '. %s && %s' "$(zero_shell_quote "$1")" "$zero_cmd"
}

download_zero_package() {
	version="$1"
	tag="$2"
	download_dir="$3"

	if ! command -v curl >/dev/null 2>&1; then
		printf 'error: curl is required to download Zero.\n' >&2
		exit 1
	fi
	if ! zero_run_quiet_with_animation \
		"Downloading Zero" \
		"Downloading Zero packages" \
		"Zero v$version" \
		zero_download_artifacts "$version" "$tag" "$download_dir"; then
		printf 'error: could not download the Zero release artifacts from the %s release.\n' "$tag" >&2
		exit 1
	fi

	verify_zero_package_checksums "$download_dir"
}

zero_download_artifacts() {
	version="$1"
	tag="$2"
	download_dir="$3"
	pids=
	for artifact_name in "$zero_package-$version.tgz" "zero-ai-$version.tgz" "zero-core-$version.tgz" \
		"zero-tui-$version.tgz" SHA256SUMS; do
		curl -fsSL $zero_curl_retry "https://github.com/$zero_repo/releases/download/$tag/$artifact_name" \
			-o "$download_dir/$artifact_name" &
		pids="$pids $!"
	done
	download_status=0
	for pid in $pids; do
		wait "$pid" || download_status=1
	done
	return "$download_status"
}

# Checks every tarball in the download directory against SHA256SUMS at once —
# the four release tarballs (main package + its zero-ai/zero-core/zero-tui
# dependencies) all need to be present and verified for the main package's
# relative file: dependencies to resolve correctly at install time.
verify_zero_package_checksums() {
	download_dir="$1"

	if command -v sha256sum >/dev/null 2>&1; then
		zero_run_quiet_with_animation \
			"Verifying download" \
			"Verifying Zero download" \
			"Checking SHA-256." \
			zero_run_checksum_check "$download_dir" SHA256SUMS sha256sum
	elif command -v shasum >/dev/null 2>&1; then
		zero_run_quiet_with_animation \
			"Verifying download" \
			"Verifying Zero download" \
			"Checking SHA-256." \
			zero_run_checksum_check "$download_dir" SHA256SUMS shasum
	else
		printf 'error: sha256sum or shasum is required to verify the Zero download.\n' >&2
		exit 1
	fi
}

zero_run_checksum_check() {
	checksum_dir="$1"
	selected_checksums_name="$2"
	checker="$3"
	case "$checker" in
		sha256sum)
			(cd "$checksum_dir" && sha256sum -c "$selected_checksums_name")
			;;
		shasum)
			(cd "$checksum_dir" && shasum -a 256 -c "$selected_checksums_name")
			;;
	esac
}

zero_npm_prefix_lookup() {
	command -v npm >/dev/null 2>&1 || return 0
	npm prefix -g 2>/dev/null || true
}

zero_installed_version() {
	[ -n "$zero_npm_prefix" ] || return 0
	pkg_json="$zero_npm_prefix/lib/node_modules/$zero_package/package.json"
	[ -f "$pkg_json" ] || return 0
	while IFS= read -r pkg_line; do
		case "$pkg_line" in
			*'"version"'*)
				pkg_version=${pkg_line#*\"version\"}
				pkg_version=${pkg_version#*\"}
				printf '%s' "${pkg_version%%\"*}"
				return 0
				;;
		esac
	done <"$pkg_json"
}

assert_no_conflicting_zero_install() {
	existing=$(command -v "$zero_cmd" 2>/dev/null || true)
	[ -n "$existing" ] || return 0
	if [ -n "$zero_npm_prefix" ]; then
		case "$existing" in
			"$zero_npm_prefix"/*) return 0 ;;
		esac
	fi
	printf 'error: another %s install is already on your PATH at: %s\n' "$zero_cmd" "$existing" >&2
	printf 'Remove it (or uninstall it with the tool that installed it), then run this installer again.\n' >&2
	exit 1
}

confirm_install() {
	version="$1"
	tag="$2"
	installed_version="$3"

	if [ -n "$installed_version" ]; then
		install_prompt="Update Zero from v$installed_version to v$version globally with npm?"
	else
		install_prompt="Install Zero v$version globally with npm?"
	fi

	if zero_prompt_yes_no \
		"$install_prompt" \
		"Downloads the verified release and runs npm install -g." \
		"Install? [Y/n]"; then
		return 0
	else
		prompt_status=$?
	fi

	if [ "$prompt_status" -eq 2 ]; then
		printf 'This will download, verify, and install Zero v%s from:\n\n  https://github.com/%s/releases/tag/%s\n\n' \
			"$version" "$zero_repo" "$tag"
		printf 'No terminal detected; continuing without confirmation.\n'
		return 0
	fi

	if [ "$zero_screen_enabled" = 1 ]; then
		zero_screen "Installation cancelled" "" "No changes were made." ""
		exit 0
	fi
	printf '\nInstallation cancelled.\n'
	exit 0
}

confirm_kernel_runtime_setup() {
	case "${ZERO_BOOTSTRAP_KERNEL_ON_INSTALL:-}" in
		1)
			zero_bootstrap_kernel_on_install=1
			return
			;;
		0)
			zero_bootstrap_kernel_on_install=0
			return
			;;
	esac

	if zero_prompt_yes_no \
		"Prepare IPython runtime now?" \
		"Installs uv, Python 3.11, ipykernel, and Zero runtime." \
		"Prepare? [Y/n]"; then
		zero_bootstrap_kernel_on_install=1
		return
	else
		prompt_status=$?
	fi

	if [ "$prompt_status" -eq 2 ]; then
		printf 'No terminal detected; preparing the IPython runtime during install.\n'
		zero_bootstrap_kernel_on_install=1
		return
	fi

	zero_bootstrap_kernel_on_install=0
	if [ "$zero_screen_enabled" = 1 ]; then
		zero_screen "IPython setup skipped" "" "The runtime can be prepared on first ipython use." ""
		sleep 0.4
	else
		printf '\nSkipping IPython runtime setup.\n'
	fi
}

install_zero_package() {
	tarball_path="$1"
	if [ "$zero_bootstrap_kernel_on_install" = 1 ]; then
		npm_install_details="Preparing global install.
Linking command binaries.
Installing runtime packages.
Preloading search tools.
Preparing IPython kernel.
Finalizing npm install."
		zero_install_zero_with_retry \
			"$npm_install_details" \
			env ZERO_BOOTSTRAP_TOOLS_ON_INSTALL=1 ZERO_BOOTSTRAP_KERNEL_ON_INSTALL=1 ZERO_INSTALL_UV=1 npm install -g --no-fund --no-audit --loglevel=error --progress=false "$tarball_path"
	else
		npm_install_details="Preparing global install.
Linking command binaries.
Installing runtime packages.
Preloading search tools.
Finalizing npm install."
		zero_install_zero_with_retry \
			"$npm_install_details" \
			env ZERO_BOOTSTRAP_TOOLS_ON_INSTALL=1 npm install -g --no-fund --no-audit --loglevel=error --progress=false "$tarball_path"
	fi
}

# Installs Zero via npm. A fresh machine's global npm directory is sometimes
# only writable by root (common when Node came from a distro package manager).
# On that failure this retries once with elevated privileges, and only ever
# shows the person a plain explanation -- never npm's raw error output, which
# would be meaningless noise to someone who has never used a terminal before.
zero_install_zero_with_retry() {
	details="$1"
	shift

	if zero_run_quiet_with_animation_command "Installing Zero" "Installing Zero" "$details" static 1 "$@"; then
		return 0
	fi
	install_status=$?

	if [ "$zero_last_quiet_command_permission_error" != 1 ]; then
		zero_print_npm_failure_help 0
		return "$install_status"
	fi
	if [ "${EUID:-$(id -u)}" -eq 0 ]; then
		# Already ran with full permission once; nothing left to retry with.
		zero_print_npm_failure_help 1
		return "$install_status"
	fi
	if ! zero_has_sudo && ! zero_has_su; then
		# No way to request elevated permission on this system; never attempted it.
		zero_print_npm_failure_help 0
		return "$install_status"
	fi

	zero_screen "Installing Zero" "" "Your account needs permission for this step." ""
	zero_restore_terminal
	printf '\nZero needs permission to install for everyone on this computer.\n'
	if zero_has_sudo; then
		sudo -v
	else
		su -c true
	fi

	if zero_run_quiet_with_animation_command "Installing Zero" "Installing Zero" "$details" static 1 run_with_sudo "$@"; then
		return 0
	fi
	retry_status=$?
	zero_print_npm_failure_help 1
	return "$retry_status"
}

zero_print_npm_failure_help() {
	retried="$1"
	printf '\n'
	if [ "$retried" = 1 ]; then
		printf 'Zero could not finish installing, even with extra permission.\n'
	else
		printf 'Zero could not finish installing.\n'
	fi
	printf 'This usually clears up by restarting your terminal and running this installer again.\n'
	if [ -n "$zero_last_quiet_command_log_path" ]; then
		printf 'If it keeps happening, share this file when asking for help: %s\n' "$zero_last_quiet_command_log_path"
	fi
	printf '\n'
}

main "$@"
