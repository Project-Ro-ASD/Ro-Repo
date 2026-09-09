#!/usr/bin/env python3
import hashlib, json, pathlib, subprocess, sys
directory=pathlib.Path(sys.argv[1]); output=pathlib.Path(sys.argv[2]); items=[]
for path in sorted(directory.glob('*.rpm')):
    q='%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\t%|SOURCEPACKAGE?{true}:{false}|'
    name,epoch,version,release,arch,source,is_source=subprocess.check_output(['rpm','-qp','--qf',q,str(path)],text=True).split('\t')
    if is_source=='true': arch='src'; source=None
    items.append({'filename':path.name,'name':name,'epoch':int(epoch or 0),'version':version,'release':release,'architecture':arch,'source_rpm':source,'producer_artifact_sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
manifest={'schema_version':1,'component':'ro-control','source_repository':'Project-Ro-ASD/ro-Control','source_commit':'a'*40,'release_tag':'v9.9.9','release_id':'local-test-1','workflow_run':'local-test-1','fedora_release':44,'artifacts':items,'provenance':{'provider':'local-test','subject_digest':'b'*64},'attestation':{'provider':'local-test','verification':'local-test'},'sbom':None}
output.write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
