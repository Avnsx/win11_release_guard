
    (function(){
      var dataNode=document.getElementById('policy-freshness-data');
      var panelNode=document.getElementById('live-freshness-panel');
      var stateNode=document.getElementById('live-freshness-state');
      var ageNode=document.getElementById('live-generated-age');
      var detailNode=document.getElementById('live-freshness-detail');
      var ringNode=panelNode ? panelNode.querySelector('.freshness-ring') : null;
      var detailTextNode=detailNode ? detailNode.querySelector('.freshness-callout-text') : null;
      var uiActive=true;
      var uiFrames=[];
      var uiTimers=[];
      function reportUiError(scope,error){
        try{
          var root=document.documentElement;
          var label=String(scope||'unknown');
          if(root){
            if(root.dataset){root.dataset.uiLastError=label;}
            root.setAttribute('data-ui-last-error',label);
            var count=Number(root.getAttribute('data-ui-error-count')||'0');
            if(!Number.isFinite(count)||count<0){count=0;}
            root.setAttribute('data-ui-error-count',String(count+1));
          }
        }catch(_markerError){}
        try{if(window.console&&console.warn){console.warn('Windows 11 Release Guard UI '+label+' failed');}}catch(_consoleError){}
      }
      function reportMissingNode(scope,name){reportUiError(scope+' missing '+name,new Error('missing '+name));}
      function guard(scope,fn){try{return fn();}catch(error){reportUiError(scope,error);return undefined;}}
      function safeSetTimeout(fn,delay){
        if(!uiActive){return 0;}
        try{
          var id=window.setTimeout(function(){if(uiActive){guard('timer callback',fn);}},delay);
          uiTimers.push(['timeout',id]);
          return id;
        }catch(error){reportUiError('timer setup',error);return 0;}
      }
      function safeSetInterval(fn,delay){
        if(!uiActive){return 0;}
        try{
          var id=window.setInterval(function(){if(uiActive){guard('interval callback',fn);}},delay);
          uiTimers.push(['interval',id]);
          return id;
        }catch(error){reportUiError('interval setup',error);return 0;}
      }
      function safeRequestFrame(fn){
        if(!uiActive){return 0;}
        if(!window.requestAnimationFrame){return safeSetTimeout(fn,16);}
        try{
          var id=window.requestAnimationFrame(function(){if(uiActive){guard('animation frame',fn);}});
          uiFrames.push(id);
          return id;
        }catch(error){reportUiError('animation frame request',error);return safeSetTimeout(fn,16);}
      }
      function safeCancelFrame(id){
        if(!id){return;}
        try{if(window.cancelAnimationFrame){window.cancelAnimationFrame(id);}else{window.clearTimeout(id);}}
        catch(error){reportUiError('animation cancel',error);}
      }
      function shutdownUi(){
        if(!uiActive){return;}
        uiActive=false;
        uiFrames.forEach(safeCancelFrame);
        uiFrames=[];
        uiTimers.forEach(function(entry){try{if(entry[0]==='interval'){window.clearInterval(entry[1]);}else{window.clearTimeout(entry[1]);}}catch(error){reportUiError('timer cancel',error);}});
        uiTimers=[];
      }
      window.addEventListener('pagehide',function(){guard('shutdown',shutdownUi);},{once:true});
      window.addEventListener('beforeunload',function(){guard('shutdown',shutdownUi);},{once:true});
      function setText(node,value,scope){if(uiActive&&node&&node.isConnected){node.textContent=value;return;}if(uiActive&&scope){reportMissingNode(scope,'text target');}}
      function setState(state,label,detail,detailLabel){
        if(!uiActive){return;}
        if(panelNode&&panelNode.isConnected){panelNode.setAttribute('data-freshness-state',state);}else{reportMissingNode('freshness state','panel');}
        if(ringNode&&ringNode.isConnected){ringNode.className='freshness-ring '+state;}else{reportMissingNode('freshness state','ring');}
        if(detailNode&&detailNode.isConnected){detailNode.className='freshness-detail freshness-callout '+state;detailNode.setAttribute('aria-label',detailLabel||detail);}else{reportMissingNode('freshness state','detail');}
        if(stateNode&&stateNode.isConnected){stateNode.className='freshness-state '+state;stateNode.textContent=label;stateNode.setAttribute('aria-label','Published policy feed currency: '+label);}else{reportMissingNode('freshness state','label');}
        var detailTarget=(detailTextNode&&detailTextNode.isConnected) ? detailTextNode : detailNode;
        setText(detailTarget,detail,'freshness detail');
      }
      function plural(value,unit){return value+' '+unit+(value===1?'':'s');}
      function exactAge(seconds){
        var days=Math.floor(seconds/86400);
        var hours=Math.floor((seconds%86400)/3600);
        var minutes=Math.floor((seconds%3600)/60);
        var parts=[];
        if(days){parts.push(plural(days,'day'));}
        if(hours||days){parts.push(plural(hours,'hour'));}
        parts.push(plural(minutes,'minute'));
        return parts.join(', ');
      }
      function formatAge(seconds){
        seconds=Number(seconds);
        if(!Number.isFinite(seconds)||seconds<0){return {text:'unknown',size:'age-wide',full:'Published feed age unknown'};}
        seconds=Math.max(0,Math.floor(seconds));
        var days=Math.floor(seconds/86400);
        var hours=Math.floor((seconds%86400)/3600);
        var minutes=Math.floor((seconds%3600)/60);
        var full='Published feed age '+exactAge(seconds);
        if(days>=1){return {text:days+'d '+hours+'h',size:days>=10?'age-compact':'age-wide',full:full};}
        var hourValue=seconds/3600;
        if(hourValue>=2){return {text:hourValue.toFixed(1).replace(/\.0$/,'')+' hours',size:hourValue>=10?'age-wide':'',full:full};}
        return {text:plural(minutes,'minute'),size:minutes>=100?'age-wide':'',full:full};
      }
      function setAgeDisplay(age){
        if(!uiActive){return;}
        if(!ageNode||!ageNode.isConnected){reportMissingNode('freshness age','metric');return;}
        ageNode.textContent=age.text;
        ageNode.className='freshness-metric'+(age.size?' '+age.size:'');
        ageNode.setAttribute('title',age.full);
        ageNode.setAttribute('aria-label',age.full);
      }
      function fallbackCopy(text){
        if(!uiActive){return Promise.reject(new Error('ui inactive'));}
        if(!document.body){reportMissingNode('copy fallback','body');return Promise.reject(new Error('copy unavailable'));}
        var area=document.createElement('textarea');
        area.value=text;area.setAttribute('readonly','');
        area.style.position='fixed';area.style.left='-9999px';
        var ok=false;
        try{document.body.appendChild(area);area.select();ok=Boolean(document.execCommand&&document.execCommand('copy'));}catch(_error){ok=false;}finally{if(area.parentNode){area.parentNode.removeChild(area);}}
        return ok ? Promise.resolve() : Promise.reject(new Error('copy failed'));
      }
      function copyText(text){
        if(!uiActive){return Promise.reject(new Error('ui inactive'));}
        try{if(navigator.clipboard&&navigator.clipboard.writeText){return navigator.clipboard.writeText(text);}}catch(_error){return fallbackCopy(text);}
        return fallbackCopy(text);
      }
      function markCopyButton(button,state,title){
        if(!uiActive){return;}
        if(!button||!button.isConnected){reportMissingNode('copy button','button');return;}
        button.setAttribute('data-copy-state',state);
        button.setAttribute('title',title);
        safeSetTimeout(function(){if(button&&button.isConnected){button.removeAttribute('data-copy-state');button.setAttribute('title',button.getAttribute('data-default-title')||'Copy epoch millisecond timestamp');}},1600);
      }
      Array.prototype.forEach.call(document.querySelectorAll('.epoch-copy[data-epoch]'),function(button){
        button.setAttribute('data-default-title',button.getAttribute('title')||'Copy epoch millisecond timestamp');
        button.addEventListener('click',function(){guard('copy epoch',function(){
          if(!uiActive||!button.isConnected){return;}
          var epoch=button.getAttribute('data-epoch')||'';
          if(!/^\d+$/.test(epoch)){markCopyButton(button,'failed','Epoch millisecond timestamp unavailable');return;}
          copyText(epoch).then(function(){markCopyButton(button,'copied','Copied epoch millisecond timestamp '+epoch);}).catch(function(){markCopyButton(button,'failed','Could not copy epoch millisecond timestamp');});
        });});
      });
      function initBaselineUpdateNotice(){
        var notice=document.querySelector('[data-baseline-notice="active"]');
        if(!notice){return;}
        if(!notice.isConnected){reportMissingNode('baseline update notice timer','notice');return;}
        var until=notice.getAttribute('data-baseline-notice-visible-until')||'';
        if(!until){reportMissingNode('baseline update notice timer','expiry marker');return;}
        var expiry=Date.parse(until);
        if(!Number.isFinite(expiry)){return;}
        function updateBaselineNoticeVisibility(){
          if(!uiActive||!notice.isConnected){return;}
          var remaining=expiry-Date.now();
          if(remaining<=0){
            notice.hidden=true;
            notice.setAttribute('aria-hidden','true');
            var grid=notice.closest ? notice.closest('.dashboard-grid') : null;
            if(grid&&grid.isConnected){grid.classList.remove('has-baseline-notice');}
            else{reportMissingNode('baseline update notice timer','dashboard grid');}
            return;
          }
          safeSetTimeout(updateBaselineNoticeVisibility,Math.min(Math.max(remaining+1000,1000),3600000));
        }
        updateBaselineNoticeVisibility();
      }
      guard('baseline update notice timer',initBaselineUpdateNotice);
      function initDiagnosticFilters(){
        var root=document.querySelector('[data-diagnostic-filter-root]');
        if(!root||!root.isConnected){reportMissingNode('source diagnostics filter','root');return;}
        var feed=document.getElementById('source-diagnostics-feed');
        if(!feed||!feed.isConnected){reportMissingNode('source diagnostics filter','feed');return;}
        var controls=root.querySelectorAll('[data-diagnostic-filter]');
        var rows=root.querySelectorAll('.diag-row[data-diagnostic-severity]');
        if(!controls.length){reportMissingNode('source diagnostics filter','controls');return;}
        if(!rows.length){reportMissingNode('source diagnostics filter','rows');return;}
        var status=document.getElementById('source-diagnostics-filter-status');
        var empty=document.getElementById('source-diagnostics-empty');
        var moreBlocks=root.querySelectorAll('.diag-more');
        var labels={notice:'notice',warning:'warning',error:'error'};
        var grid=root.closest ? root.closest('.dashboard-grid') : null;
        var programmatic=grid ? grid.querySelector('.programmatic-api') : document.querySelector('.programmatic-api');
        var expandToggle=root.querySelector('[data-diagnostics-expand-toggle="true"]');
        var exportCopy=root.querySelector('[data-diagnostics-copy="visible-json"]');
        var diagnosticsExpanded=false;
        if(!expandToggle||!expandToggle.isConnected){reportMissingNode('source diagnostics expansion','expand toggle');}
        if(!exportCopy||!exportCopy.isConnected){reportMissingNode('source diagnostics export copy','button');}
        function rowWord(count){return count===1?'row':'rows';}
        function normalizedFilter(value){return labels[value] ? value : '';}
        function compactText(node){return node ? (node.textContent||'').replace(/\s+/g,' ').trim() : '';}
        function elementDisplayed(element){
          if(!element||!element.isConnected){return false;}
          var current=element;
          while(current&&current!==root){
            if(current.hidden){return false;}
            if(current.tagName&&current.tagName.toLowerCase()==='details'&&!current.open){return false;}
            current=current.parentElement;
          }
          return true;
        }
        function dashboardDiagnosticCounts(){
          var counts={notice:0,warning:0,error:0};
          Array.prototype.forEach.call(root.querySelectorAll('.diag-tile[data-diagnostic-severity]'),function(tile){
            if(!tile||!tile.isConnected){return;}
            var severity=normalizedFilter(tile.getAttribute('data-diagnostic-severity')||'');
            var value=Number(compactText(tile.querySelector('strong')));
            if(severity&&Number.isFinite(value)){counts[severity]=value;}
          });
          return counts;
        }
        function visibleDiagnosticEntries(){
          var entries=[];
          Array.prototype.forEach.call(rows,function(row,index){
            if(!elementDisplayed(row)){return;}
            var severity=normalizedFilter(row.getAttribute('data-diagnostic-severity')||'')||'notice';
            var tags=[];
            Array.prototype.forEach.call(row.querySelectorAll('.diag-tags span,.diag-tags a'),function(tag){var text=compactText(tag);if(text){tags.push(text);}});
            var issueLink=row.querySelector('.diag-ticket-link[href]');
            var entry={
              severity:severity,
              diagnostic_id:row.getAttribute('data-diagnostic-id')||'',
              title:compactText(row.querySelector('.diag-row-head strong'))||'Source diagnostic',
              source:compactText(row.querySelector('.source-chip'))||'Source',
              message:compactText(row.querySelector('.diag-technical-message'))||compactText(row.querySelector('p')),
              tags:tags,
              issue_url:issueLink ? (issueLink.getAttribute('href')||null) : null,
              display_index:index+1
            };
            function addAttr(attr,key){var value=row.getAttribute(attr)||'';if(value){entry[key]=value;}}
            function addListAttr(attr,key){var value=row.getAttribute(attr)||'';if(value){entry[key]=value.split(',').map(function(item){return item.trim();}).filter(Boolean);}}
            addAttr('data-user-message','user_message');
            addAttr('data-kb-update-bucket','kb_update_bucket');
            addAttr('data-kb-update-bucket-confidence','kb_update_bucket_confidence');
            addAttr('data-security-evidence-source','security_evidence_source');
            addAttr('data-support-article-url','support_article_url');
            addAttr('data-source-url','source_url');
            addAttr('data-msrc-cvrf-url','msrc_cvrf_url');
            addAttr('data-read-more-url','read_more_url');
            addAttr('data-security-url','security_url');
            addAttr('data-support-article-validation-status','support_article_validation_status');
            addListAttr('data-support-article-validation-reasons','support_article_validation_reasons');
            addAttr('data-support-article-expected-kb','support_article_expected_kb');
            addAttr('data-support-article-expected-build','support_article_expected_build');
            addAttr('data-support-article-expected-release','support_article_expected_release');
            addListAttr('data-support-article-applies-to-releases','support_article_applies_to_releases');
            addAttr('data-atom-entry-id','atom_entry_id');
            addAttr('data-atom-support-article-id','atom_support_article_id');
            var isSecurity=row.getAttribute('data-is-security');
            if(isSecurity==='true'){entry.is_security=true;}else if(isSecurity==='false'){entry.is_security=false;}
            entries.push(entry);
          });
          return entries;
        }
        function sourceDiagnosticsExportPayload(){
          var entries=visibleDiagnosticEntries();
          var visibleCounts={notice:0,warning:0,error:0};
          entries.forEach(function(entry){if(labels[entry.severity]){visibleCounts[entry.severity]+=1;}});
          return {
            export_schema:'win11_release_guard.source_diagnostics.visible.v1',
            product:'win11_release_guard',
            exported_at_utc:new Date().toISOString(),
            page_url:String(window.location.href||''),
            active_filter:root.getAttribute('data-active-diagnostic-filter')||'all',
            status_text:status&&status.isConnected ? compactText(status) : '',
            dashboard_counts_by_severity:dashboardDiagnosticCounts(),
            visible_counts_by_severity:visibleCounts,
            visible_count:entries.length,
            context_note:'DOM export of currently visible Source Diagnostics rows for technical triage. These rows describe source, parser, drift, freshness, or dashboard-derived context and do not override signed policy verdicts.',
            entries:entries
          };
        }
        function setDiagnosticsExpanded(expanded){
          if(!uiActive||!root.isConnected){reportMissingNode('source diagnostics expansion','root');return;}
          diagnosticsExpanded=Boolean(expanded);
          root.setAttribute('data-diagnostics-expanded',diagnosticsExpanded?'true':'false');
          if(grid&&grid.isConnected){grid.classList.toggle('diagnostics-expanded',diagnosticsExpanded);}else{reportMissingNode('source diagnostics expansion','dashboard grid');}
          if(programmatic&&programmatic.isConnected){programmatic.hidden=diagnosticsExpanded;programmatic.setAttribute('aria-hidden',String(diagnosticsExpanded));}else{reportMissingNode('source diagnostics expansion','programmatic api');}
          if(expandToggle&&expandToggle.isConnected){expandToggle.setAttribute('aria-expanded',String(diagnosticsExpanded));expandToggle.setAttribute('aria-label',diagnosticsExpanded?'Collapse Source Diagnostics view':'Expand Source Diagnostics view');expandToggle.textContent=diagnosticsExpanded?'Collapse View':'Expand View';}
          Array.prototype.forEach.call(moreBlocks,function(block){if(block&&block.isConnected&&!block.hidden){block.open=diagnosticsExpanded||block.open;}});
        }
        function setFilterStatus(severity,shown){
          if(!status||!status.isConnected){reportMissingNode('source diagnostics filter','status');return;}
          if(!severity){status.textContent='Showing all '+rows.length+' source diagnostic '+rowWord(rows.length)+'.';return;}
          if(shown){status.textContent='Showing '+shown+' '+labels[severity]+' diagnostic '+rowWord(shown)+'.';return;}
          status.textContent='No '+labels[severity]+' diagnostic rows are currently reported.';
        }
        function setEmptyState(severity,shown){
          if(!empty||!empty.isConnected){reportMissingNode('source diagnostics filter','empty state');return;}
          if(severity&&shown===0){empty.hidden=false;empty.textContent='This category currently contains no entries.';return;}
          empty.hidden=true;
        }
        function updateOverflow(severity){
          Array.prototype.forEach.call(moreBlocks,function(block){
            if(!block||!block.isConnected){return;}
            var hasVisible=false;
            Array.prototype.forEach.call(block.querySelectorAll('.diag-row[data-diagnostic-severity]'),function(row){if(!row.hidden){hasVisible=true;}});
            if(severity){block.hidden=!hasVisible;if(hasVisible){block.open=true;}return;}
            block.hidden=false;block.open=diagnosticsExpanded;
          });
        }
        function setPressedState(severity){
          Array.prototype.forEach.call(controls,function(control){
            if(!control||!control.isConnected){return;}
            var value=control.getAttribute('data-diagnostic-filter')||'';
            control.setAttribute('aria-pressed',severity ? String(value===severity) : String(value==='all'));
          });
        }
        function applyFilter(value){
          if(!uiActive||!root.isConnected||!feed.isConnected){return;}
          var severity=normalizedFilter(value);
          root.setAttribute('data-active-diagnostic-filter',severity||'all');
          var shown=0;
          Array.prototype.forEach.call(rows,function(row){
            if(!row||!row.isConnected){return;}
            var match=!severity||row.getAttribute('data-diagnostic-severity')===severity;
            row.hidden=!match;
            row.classList.toggle('is-filtered-out',!match);
            if(match){shown+=1;}
          });
          updateOverflow(severity);
          setEmptyState(severity,shown);
          setFilterStatus(severity,shown);
          setPressedState(severity);
        }
        Array.prototype.forEach.call(controls,function(control){
          control.addEventListener('click',function(event){guard('source diagnostics filter',function(){
            if(event&&event.preventDefault){event.preventDefault();}
            if(!uiActive||!control.isConnected){return;}
            applyFilter(control.getAttribute('data-diagnostic-filter')||'all');
          });});
        });
        if(expandToggle&&expandToggle.isConnected){expandToggle.addEventListener('click',function(event){guard('source diagnostics expansion',function(){
          if(event&&event.preventDefault){event.preventDefault();}
          if(!uiActive||!expandToggle.isConnected){return;}
          setDiagnosticsExpanded(!diagnosticsExpanded);
          updateOverflow(normalizedFilter(root.getAttribute('data-active-diagnostic-filter')||''));
        });});}
        if(exportCopy&&exportCopy.isConnected){
          exportCopy.setAttribute('data-default-title',exportCopy.getAttribute('title')||'Copy visible Source Diagnostics JSON');
          exportCopy.addEventListener('click',function(event){guard('source diagnostics export copy',function(){
            if(event&&event.preventDefault){event.preventDefault();}
            if(!uiActive||!exportCopy.isConnected){return;}
            var payload=sourceDiagnosticsExportPayload();
            copyText(JSON.stringify(payload,null,2)).then(function(){markCopyButton(exportCopy,'copied','Copied visible Source Diagnostics JSON');}).catch(function(){markCopyButton(exportCopy,'failed','Could not copy Source Diagnostics JSON');});
          });});
        }
        applyFilter('all');
      }
      guard('source diagnostics filter init',initDiagnosticFilters);
      function initHeaderNav(){
        var nav=document.querySelector('.header-nav');
        if(!nav){reportMissingNode('header nav','nav');return;}
        var items=nav.querySelectorAll('.nav-inner a');
        if(!items.length){reportMissingNode('header nav','items');return;}
        var frame=0;
        var label=nav.querySelector('.nav-hover-label');
        function setItem(item,x,y){
          if(!uiActive||!nav.isConnected||!item||!item.isConnected){return;}
          var navRect=nav.getBoundingClientRect();
          var rect=item.getBoundingClientRect();
          var text=item.getAttribute('data-nav-label')||item.getAttribute('aria-label')||'';
          nav.style.setProperty('--enter-nav','1');
          nav.style.setProperty('--label-x',String((rect.left-navRect.left)+(rect.width/2)+(x*5))+'px');
          nav.style.setProperty('--label-y',String(y*3)+'px');
          if(label&&label.isConnected&&text){label.textContent=text;}
        }
        function queue(item,event){
          if(!uiActive||!item||!item.isConnected||!event){return;}
          if(frame){safeCancelFrame(frame);}
          frame=safeRequestFrame(function(){
            frame=0;
            if(!uiActive||!item.isConnected){return;}
            var rect=item.getBoundingClientRect();
            var x=((event.clientX-rect.left)-(rect.width/2))/rect.width;
            var y=((event.clientY-rect.top)-(rect.height/2))/rect.height;
            setItem(item,Math.max(-.5,Math.min(.5,x)),Math.max(-.5,Math.min(.5,y)));
          });
        }
        Array.prototype.forEach.call(items,function(item,index){
          item.addEventListener('pointermove',function(event){guard('header nav pointer',function(){queue(item,event);});},{passive:true});
          item.addEventListener('focus',function(){guard('header nav focus',function(){setItem(item,0,0);});});
        });
        nav.addEventListener('pointerleave',function(){guard('header nav leave',function(){if(nav.isConnected){nav.style.setProperty('--enter-nav','0');}else{reportMissingNode('header nav','nav');}});});
        nav.addEventListener('focusout',function(){guard('header nav focusout',function(){safeSetTimeout(function(){if(uiActive&&nav.isConnected&&!nav.contains(document.activeElement)){nav.style.setProperty('--enter-nav','0');}},0);});});
      }
      guard('header nav init',initHeaderNav);
      function update(){
        if(!uiActive){return;}
        var data;
        if(!dataNode||!dataNode.isConnected){reportMissingNode('freshness update','data');data={};}
        else{try{data=JSON.parse(dataNode.textContent||'{}');}catch(error){data={};reportUiError('freshness data parse',error);}}
        var generated=Number(data.generated_at_epoch_s);
        if(!Number.isFinite(generated)||generated<=0){setAgeDisplay(formatAge(NaN));setState('unknown','Unknown','Policy feed timestamp is unavailable or invalid.');return;}
        var now=Math.floor(Date.now()/1000);
        if(!Number.isFinite(now)){setAgeDisplay(formatAge(NaN));setState('unknown','Unknown','Browser time is unavailable, so feed age cannot be calculated.');return;}
        if(generated-now>300){setAgeDisplay(formatAge(0));setState('unknown','Clock Check','Browser clock is behind the policy timestamp; feed age is clamped to zero.');return;}
        var ageSeconds=Math.max(0,now-generated);
        var warningSeconds=Number(data.warning_age_seconds);
        if(!Number.isFinite(warningSeconds)||warningSeconds<=0){warningSeconds=1209600;reportUiError('freshness warning threshold',new Error('invalid warning threshold'));}
        var staleSeconds=Number(data.strict_stale_age_seconds);
        if(!Number.isFinite(staleSeconds)||staleSeconds<=0){staleSeconds=3888000;reportUiError('freshness stale threshold',new Error('invalid stale threshold'));}
        setAgeDisplay(formatAge(ageSeconds));
        if(ageSeconds>=staleSeconds){setState('stale','Stale','Feed is stale. Refresh automation before trusting it.','Published policy feed is stale. Do not treat this data as production-current until automation refresh succeeds.');return;}
        if(ageSeconds>=warningSeconds){setState('refresh-due','Refresh Due','Refresh is due. Verify automation health before production use.','Published policy feed refresh is due. Verify automation health before treating this data as production-current.');return;}
        setState('current','Current','Within the {{default_policy_warning_age_days_2}}-day maintenance threshold.','Published policy feed is within the {{default_policy_warning_age_days_3}}-day maintenance threshold.');
      }
      guard('freshness update',update);
      safeSetInterval(function(){guard('freshness update',update);},60000);
    }());
  
