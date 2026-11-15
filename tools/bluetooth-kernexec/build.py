"""Recompile exactly one open-source XNU file with real Apple typed builtins."""
from pathlib import Path
import hashlib,json,subprocess
R=Path.cwd();T=R/'target';S=R/'tools/bluetooth-kernexec';O=R/'out'
manifest=json.loads((S/'source.json').read_text())
source=T/'xnu/bsd/kern/kern_exec.c'
assert hashlib.sha256(source.read_bytes()).hexdigest()==manifest['original_sha256']
subprocess.run(['patch','--batch','--fuzz=0','-p1','-i',str(S/'native-exec.patch')],cwd=T/'xnu',check=True)
assert hashlib.sha256(source.read_bytes()).hexdigest()==manifest['patched_sha256']
ci='/Users/runner/work/data-a-live/data-a-live/dxb'
original=json.loads((S/'original-command.json').read_text())
compiler=subprocess.check_output(['xcrun','--find','clang'],text=True).strip()
args=[compiler]
for a in original[1:]:
    if 'Kernel.framework/Versions/A/PrivateHeaders/platform' in a:
        a='-I'+str(T/'sdk-kernel-platform/platform')
    else:a=a.replace(ci,str(T))
    assert '__builtin_xnu_' not in a
    args.append(a)
args+=['-o',str(O/'kern_exec.o')]
version=subprocess.check_output([compiler,'--version'],text=True)
result=subprocess.run(args,cwd=T/'build/xnu.obj/DEVELOPMENT_ARM64_PANDORA/bsd/DEVELOPMENT',capture_output=True,text=True)
(O/'compile.log').write_text(result.stdout+result.stderr)
if result.returncode:raise SystemExit(result.stderr[-8000:])
report={'compiled':True,'real_apple_allocator_builtins':True,'builtin_overrides':[],
        'original_ci_run':43012468378,'source_sha256':manifest['patched_sha256'],
        'object_sha256':hashlib.sha256((O/'kern_exec.o').read_bytes()).hexdigest(),
        'compiler':version,'command':args,'hardware_tested':False}
(O/'report.json').write_text(json.dumps(report,indent=2)+'\n')
exit_manifest=json.loads((S/'exit-source.json').read_text())
exit_source=T/'xnu/bsd/kern/kern_exit.c'
assert hashlib.sha256(exit_source.read_bytes()).hexdigest()==exit_manifest['original_sha256']
subprocess.run(['patch','--batch','--fuzz=0','-p1','-i',str(S/'native-exit.patch')],cwd=T/'xnu',check=True)
assert hashlib.sha256(exit_source.read_bytes()).hexdigest()==exit_manifest['patched_sha256']
exit_args=[a.replace('kern_exec.c','kern_exit.c').replace('kern_exec.d','kern_exit.d').replace('kern_exec.o','kern_exit.o') for a in args]
result=subprocess.run(exit_args,cwd=T/'build/xnu.obj/DEVELOPMENT_ARM64_PANDORA/bsd/DEVELOPMENT',capture_output=True,text=True)
(O/'exit-compile.log').write_text(result.stdout+result.stderr)
if result.returncode:raise SystemExit(result.stderr[-8000:])
(O/'exit-report.json').write_text(json.dumps({'compiled':True,'real_apple_allocator_builtins':True,'builtin_overrides':[],
    'source_sha256':exit_manifest['patched_sha256'],'object_sha256':hashlib.sha256((O/'kern_exit.o').read_bytes()).hexdigest(),
    'command':exit_args,'compiler':version,'hardware_tested':False},indent=2)+'\n')
print('PASS: native exec hook compiled by Apple clang with original typed allocator builtins')
