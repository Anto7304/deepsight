"""Trivy and Grype exports normalize into observed package findings."""
import json


def parse_scanner(content,kind):
    data=json.loads(content)
    if not isinstance(data,dict):raise ValueError('Scanner export must be an object')
    findings=[];software=[]
    if kind=='trivy':
        if not isinstance(data.get('Results'), list):raise ValueError('Trivy export requires a Results array')
        artifact=data.get('ArtifactName') or data.get('Metadata',{}).get('ImageID') or None
        for result in data.get('Results') or []:
            for v in result.get('Vulnerabilities') or []:
                score=next((x.get('V3Score') for x in (v.get('CVSS') or {}).values() if x.get('V3Score') is not None),None)
                findings.append({'cve':v.get('VulnerabilityID'),'cvss':score,'description':v.get('Title'),
                                 'evidence':{'package':v.get('PkgName'),'installed':v.get('InstalledVersion'),'fixed':v.get('FixedVersion'),'target':result.get('Target')}})
                software.append({'product':v.get('PkgName'),'version':v.get('InstalledVersion')})
    else:
        if not isinstance(data.get('matches'), list):raise ValueError('Grype export requires a matches array')
        source=data.get('source') or {};target=source.get('target') or {}
        artifact=(target.get('userInput') or target.get('imageID')) if isinstance(target,dict) else str(target)
        artifact=artifact or None
        for match in data['matches']:
            v=match.get('vulnerability') or {};a=match.get('artifact') or {}
            score=next((x.get('metrics',{}).get('baseScore') for x in v.get('cvss',[]) if x.get('metrics',{}).get('baseScore') is not None),None)
            findings.append({'cve':v.get('id'),'cvss':score,'description':v.get('description'),
                             'evidence':{'package':a.get('name'),'installed':a.get('version'),'fixed':v.get('fix',{}).get('versions'),'locations':a.get('locations',[])}})
            software.append({'product':a.get('name'),'version':a.get('version'),'cpes':a.get('cpes',[])})
    if not artifact:raise ValueError('Scanner export requires a stable artifact name or image ID')
    return [{'identifiers':{'device_id':['image:'+artifact]},'category':'vulnerability_scan',
             **({'observed_at':data['CreatedAt']} if data.get('CreatedAt') else {}),
             'attributes':{'name':artifact,'type':'container','findings':findings,'software':software,
                           'assessment':{'kind':'vulnerability','status':'success','complete':True,'scope':'packages in scanner export','finding_codes':[f['cve'] for f in findings if f.get('cve')]}}}]
