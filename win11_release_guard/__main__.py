from __future__ import annotations

import json
import sys
import traceback
from typing import Sequence
from .api import check_current_system
from . import state_store
from .exceptions import WindowsReleaseCheckerError
# _cache_file_from_args, _state_dir_from_args, _stateless_from_args, _format_build_origin,
# _output_payload, _decode_json_bytes, and _public_pages_urls are re-exported: tests read them through this module.
from .cli_args import (
    _build_parser,
    _cache_file_from_args,
    _config_from_args,
    _state_dir_from_args,
    _stateless_from_args,
)
from .cli_diagnostics import (
    _diagnose_config_payload,
    _purge_state_payload,
    _self_test_payload,
    _show_state_payload,
)
from .cli_output import (
    EXIT_UNKNOWN_OR_POLICY_ERROR,
    _atomic_write_with_inplace_fallback,
    _exit_code,
    _format_build_origin,
    _output_payload,
    _print_error,
    _print_json,
    _print_pretty,
    _write_json_output,
)
from .cli_policy_source import _check_policy_source_payload, _print_policy_source_payload
from .cli_public_pages import _decode_json_bytes, _public_pages_urls
# Public names this module defined before the v0.6.0 split stay importable from it.
# pylint: disable=unused-import
from .cli_output import (
    EXIT_ABOVE_BROAD_TARGET,
    EXIT_COMPLIANT,
    EXIT_UPDATE_REQUIRED,
    RELEVANT_WUA_CLASSIFICATIONS,
)
from .cli_public_pages import PublicFetchResult
# pylint: enable=unused-import


EXIT_ARGUMENT_ERROR = 10


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        if exc.code == 0:
            return 0
        return EXIT_ARGUMENT_ERROR

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    if args.self_test:
        payload, ok = _self_test_payload()
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True))
        return 0 if ok else EXIT_UNKNOWN_OR_POLICY_ERROR

    if args.check_policy_source or args.check_public_pages:
        payload, ok = _check_policy_source_payload(args)
        _print_policy_source_payload(payload)
        return 0 if ok else EXIT_UNKNOWN_OR_POLICY_ERROR

    if args.diagnose_config:
        diagnose_payload = _diagnose_config_payload(args)
        # codeql[py/clear-text-logging-sensitive-data]
        print(json.dumps(diagnose_payload, indent=2, sort_keys=True, ensure_ascii=True))
        return 0

    if args.purge_state:
        try:
            payload = _purge_state_payload(_config_from_args(args))
            print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True))
            failed = any(
                isinstance(event, dict) and event.get("outcome") == "failed"
                for event in payload["events"]
            )
            return EXIT_UNKNOWN_OR_POLICY_ERROR if failed else 0
        except WindowsReleaseCheckerError as exc:
            _print_error(str(exc), json_output=True)
            if args.debug:
                traceback.print_exc()
            return EXIT_UNKNOWN_OR_POLICY_ERROR
        except Exception as exc:
            _print_error(str(exc), json_output=True)
            if args.debug:
                traceback.print_exc()
            return EXIT_UNKNOWN_OR_POLICY_ERROR

    if args.show_state:
        try:
            config = _config_from_args(args)
            payload = _show_state_payload(config)
            exit_code = 0
            if args.output is not None:
                data = state_store.read_state_bytes(config)
                if data is not None:
                    event = _atomic_write_with_inplace_fallback(args.output, data)
                    if event.outcome == "failed":
                        payload["detail"] = event.detail
                        exit_code = EXIT_UNKNOWN_OR_POLICY_ERROR
            print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True))
            return exit_code
        except WindowsReleaseCheckerError as exc:
            _print_error(str(exc), json_output=True)
            if args.debug:
                traceback.print_exc()
            return EXIT_UNKNOWN_OR_POLICY_ERROR
        except Exception as exc:
            _print_error(str(exc), json_output=True)
            if args.debug:
                traceback.print_exc()
            return EXIT_UNKNOWN_OR_POLICY_ERROR

    json_output = bool(args.json or args.json_pretty or args.output is not None)

    try:
        result = check_current_system(_config_from_args(args))
        if args.output is not None:
            _write_json_output(
                args.output,
                result,
                pretty=bool(args.json_pretty),
                unicode_output=bool(args.unicode),
                include_raw_wua_history=bool(args.include_raw_wua_history),
                include_raw_local_diagnostics=bool(args.include_raw_local_diagnostics),
            )
        if args.json or args.json_pretty:
            _print_json(
                result,
                pretty=bool(args.json_pretty),
                unicode_output=bool(args.unicode),
                include_raw_wua_history=bool(args.include_raw_wua_history),
                include_raw_local_diagnostics=bool(args.include_raw_local_diagnostics),
            )
        elif args.output is None or args.pretty:
            _print_pretty(result)
        return _exit_code(result.status)
    except WindowsReleaseCheckerError as exc:
        _print_error(str(exc), json_output=json_output)
        if args.debug:
            traceback.print_exc()
        return EXIT_UNKNOWN_OR_POLICY_ERROR
    except Exception as exc:
        _print_error(str(exc), json_output=json_output)
        if args.debug:
            traceback.print_exc()
        return EXIT_UNKNOWN_OR_POLICY_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
