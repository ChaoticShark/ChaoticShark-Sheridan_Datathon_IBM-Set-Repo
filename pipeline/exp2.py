"""EARLY EXPLORATION, superseded by model.py / backtest.py. Kept so results/experiments.json can be reproduced.
Note: it uses the earlier feature set, so its numbers differ slightly from the locked model.
"""
import os,sys,pickle,numpy as np,pandas as pd
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import core
from text_model import TextPrior
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.pipeline import make_pipeline
from backtest import hits_at
d=pickle.load(open(os.path.join(core.CACHE,'bt_features.pkl'),'rb'))
Xte,mte=d['Xte'],d['mte']; y=mte.label.values
path=os.path.join(core.CACHE,'bt_rolling.pkl')
if os.path.exists(path): Xr,mr,w=pickle.load(open(path,'rb'))
else:
    v,k,s=core.load_vulns(),core.load_kev(),core.load_signals()
    hist=core.KevHistory(k)
    p=core.build_rolling_pool([f"2024-{m:02d}" for m in range(1,13)],"2024-12-31",v,k,s,max_age_months=24)
    tp=TextPrior().fit(v,k,"2023-12-31"); V=v.set_index('cve_id').loc[p.cve_id.unique()]
    ts=dict(zip(V.index,tp.score(V.description,V.assigner_key)))
    Xr,mr=core.build_features(p,v,k,hist,ts,assigner_cutoff="2023-12-31"); w=p.weight.values
    Xr['age']=p.age_months.values
    pickle.dump((Xr,mr,w),open(path,'wb'))
print("rolling rows",len(Xr),"pos",mr.label.sum())
Xte=Xte.copy(); Xte['age']=0.0
def fit(X,yy,ww,C,cols):
    pp=make_pipeline(SimpleImputer(strategy="median"),StandardScaler(),LogisticRegression(C=C,class_weight="balanced",max_iter=5000))
    pp.fit(X[cols],yy,logisticregression__sample_weight=ww); return pp
allc=list(Xr.columns)
core_cols=['epss_log','epss_missing','any_exploit_code','poc_github','nuclei','metasploit','exploitdb','text_score','assigner_rate_log','kev_vendor_log','kev_product_log','vendor_matched','cvss4','kw_auth_bypass','kw_edge','kw_rce','kw_cmd_inj','kw_dos','kw_xss','kw_wp_plugin','kw_remote','kw_local','kw_needs_auth','kw_user_click','age']
k=243
for C in (0.01,0.05,0.2,1.0):
    for name,cols in (("all",allc),("core",core_cols)):
        pp=fit(Xr,mr.label.values,w,C,cols); s=pp.decision_function(Xte[cols])
        print(f"rolling LR C={C} {name}: @500={hits_at(y,s,500)} @{k}={hits_at(y,s,k)} @1000={hits_at(y,s,1000)}")
pp=fit(Xr,mr.label.values,w,0.05,core_cols)
print(dict(sorted(zip(core_cols,pp[-1].coef_[0].round(2)),key=lambda t:-abs(t[1]))))
from ranker import Ranker
Xtr,mtr=d['Xtr'],d['mtr']; m12=(mtr.fast==0).values
s1=pd.Series(fit(Xr,mr.label.values,w,0.05,core_cols).decision_function(Xte[core_cols])).rank(pct=True).values
s2=pd.Series(Ranker(0.05).fit(Xtr[m12],mtr.label[m12]).score(Xte.drop(columns=['age']))).rank(pct=True).values
for a in (0.0,0.3,0.5,0.7,1.0):
    s=a*s1+(1-a)*s2; print(f"ensemble a={a}: @500={hits_at(y,s,500)} @243={hits_at(y,s,243)} @1000={hits_at(y,s,1000)}")
