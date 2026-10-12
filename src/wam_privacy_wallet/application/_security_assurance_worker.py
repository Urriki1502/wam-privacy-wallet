"""One-shot public fixture only. Not a hostile-code or OS sandbox."""
from dataclasses import asdict
import json
import sys
from .security_assurance_review import _execute_public_fixture


def _audit(event,args):
    if event.startswith('socket.') or event in ('subprocess.Popen','os.system','os.exec','os.posix_spawn'):
        raise PermissionError('PUBLIC_ASSURANCE_IO_DENIED')


def main():
    try:
        if len(sys.argv)!=1 or sys.stdin.buffer.read(129)!=b'PUBLIC_ASSURANCE_FIXTURE_V1\n':return 2
        sys.addaudithook(_audit)
        receipt=_execute_public_fixture()
        print(json.dumps(asdict(receipt),sort_keys=True))
        return 0
    except Exception:return 2


if __name__=='__main__':raise SystemExit(main())
