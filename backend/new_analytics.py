@app.get("/analytics/detailed")
async def get_detailed_analytics(token: Optional[str] = Query(None)):
    """Get detailed analytics for dashboard - redesigned for focused insights"""
    try:
        now = datetime.utcnow()
        thirty_days_ago = now - timedelta(days=30)
        
        # Verify user if token provided
        user_email = None
        if token:
            try:
                user_email = verify_token(token)
                print(f"[ANALYTICS] Fetching for user: {user_email}")
            except:
                print("[ANALYTICS] Invalid token, showing all data")
        
        # Initialize response
        analytics = {
            "vulnerability_distribution": [],
            "scan_timeline": [],
            "risk_distribution": [],
            "top_vulnerable_files": [],
            "model_performance": [],
            "security_trend": [],
            "total_scans": 0,
            "total_vulnerabilities": 0,
            "last_updated": now.isoformat()
        }
        
        if scans_collection is None:
            return analytics
        
        # Build query filter
        query_filter = {}
        if user_email:
            query_filter["user_email"] = user_email
        
        # Fetch all scans (last 100 for performance)
        all_scans = list(scans_collection.find(query_filter).sort("scan_time", -1).limit(100))
        analytics["total_scans"] = len(all_scans)
        
        # === 1. VULNERABILITY TYPE DISTRIBUTION ===
        vuln_type_counts = defaultdict(int)
        
        for scan in all_scans:
            if scan.get("vulnerable", False):
                highlights = scan.get("highlights", [])
                if isinstance(highlights, list) and highlights:
                    for h in highlights:
                        if isinstance(h, dict):
                            v_type = h.get("type", "General Vulnerability")
                            vuln_type_counts[v_type] += 1
                elif isinstance(highlights, str) and highlights:
                    # Parse old string format
                    if "SQL" in highlights or "injection" in highlights.lower():
                        vuln_type_counts["SQL Injection"] += 1
                    elif "XSS" in highlights:
                        vuln_type_counts["Cross-Site Scripting (XSS)"] += 1
                    elif "command" in highlights.lower():
                        vuln_type_counts["Command Injection"] += 1
                    elif "hardcoded" in highlights.lower():
                        vuln_type_counts["Hardcoded Credentials"] += 1
                    else:
                        vuln_type_counts["General Vulnerability"] += 1
        
        # Get top 8 vulnerability types
        top_vulns = sorted(vuln_type_counts.items(), key=lambda x: x[1], reverse=True)[:8]
        analytics["vulnerability_distribution"] = [{"name": name, "value": count} for name, count in top_vulns]
        analytics["total_vulnerabilities"] = sum(vuln_type_counts.values())
        
        # === 2. SCAN ACTIVITY TIMELINE (Last 30 days) ===
        timeline_data = defaultdict(lambda: {"total": 0, "vulnerable": 0, "clean": 0})
        
        for scan in all_scans:
            scan_date = scan.get("scan_time", "")
            if isinstance(scan_date, str):
                date_key = scan_date.split("T")[0]
            else:
                continue
            
            # Only include last 30 days
            try:
                scan_datetime = datetime.fromisoformat(scan_date.replace('Z', '+00:00'))
                if scan_datetime < thirty_days_ago:
                    continue
            except:
                pass
            
            timeline_data[date_key]["total"] += 1
            if scan.get("vulnerable", False):
                timeline_data[date_key]["vulnerable"] += 1
            else:
                timeline_data[date_key]["clean"] += 1
        
        # Fill in missing days with zeros
        for i in range(30):
            date = (now - timedelta(days=i)).strftime("%Y-%m-%d")
            if date not in timeline_data:
                timeline_data[date] = {"total": 0, "vulnerable": 0, "clean": 0}
        
        # Sort by date
        timeline_list = []
        for date in sorted(timeline_data.keys())[-30:]:
            data = timeline_data[date]
            timeline_list.append({
                "date": date,
                "total": data["total"],
                "vulnerable": data["vulnerable"],
                "clean": data["clean"]
            })
        analytics["scan_timeline"] = timeline_list
        
        # === 3. RISK SCORE DISTRIBUTION ===
        risk_ranges = {
            "0-25 (Low)": 0,
            "26-50 (Medium)": 0,
            "51-75 (High)": 0,
            "76-100 (Critical)": 0
        }
        
        for scan in all_scans:
            score = scan.get("risk_score", 0)
            if score <= 25:
                risk_ranges["0-25 (Low)"] += 1
            elif score <= 50:
                risk_ranges["26-50 (Medium)"] += 1
            elif score <= 75:
                risk_ranges["51-75 (High)"] += 1
            else:
                risk_ranges["76-100 (Critical)"] += 1
        
        analytics["risk_distribution"] = [
            {"range": range_name, "count": count}
            for range_name, count in risk_ranges.items()
        ]
        
        # === 4. TOP 10 VULNERABLE FILES (from repo scans) ===
        vulnerable_files = []
        
        if repository_scans_collection is not None:
            repo_filter = {}
            if user_email:
                repo_filter["user_email"] = user_email
            
            repo_scans = list(repository_scans_collection.find(repo_filter).sort("scan_time", -1).limit(20))
            
            for repo_scan in repo_scans:
                repo_name = repo_scan.get("repository", "unknown").split("/")[-1]
                for file_result in repo_scan.get("file_results", []):
                    if file_result.get("vulnerable", False):
                        file_path = file_result.get("file_path", "unknown")
                        file_name = file_path.split("/")[-1]
                        vulnerable_files.append({
                            "file": file_name,
                            "score": file_result.get("risk_score", 0),
                            "repo": repo_name,
                            "path": file_path
                        })
        
        # Sort by score and get top 10
        vulnerable_files.sort(key=lambda x: x["score"], reverse=True)
        analytics["top_vulnerable_files"] = vulnerable_files[:10]
        
        # === 5. MODEL PERFORMANCE COMPARISON ===
        model_stats = defaultdict(lambda: {"scans": 0, "detected": 0})
        
        for scan in all_scans:
            model = scan.get("model_used", scan.get("model", "GraphCodeBERT"))
            model_stats[model]["scans"] += 1
            if scan.get("vulnerable", False):
                model_stats[model]["detected"] += 1
        
        model_performance = []
        for model, stats in model_stats.items():
            rate = (stats["detected"] / stats["scans"] * 100) if stats["scans"] > 0 else 0
            model_performance.append({
                "model": model,
                "scans": stats["scans"],
                "detected": stats["detected"],
                "rate": round(rate, 1)
            })
        
        analytics["model_performance"] = sorted(model_performance, key=lambda x: x["scans"], reverse=True)
        
        # === 6. SECURITY SCORE TREND (Last 8 weeks) ===
        weekly_scores = defaultdict(list)
        
        for scan in all_scans:
            scan_date = scan.get("scan_time", "")
            try:
                scan_datetime = datetime.fromisoformat(scan_date.replace('Z', '+00:00'))
                weeks_ago = (now - scan_datetime).days // 7
                if weeks_ago < 8:
                    risk_score = scan.get("risk_score", 0)
                    # Invert score: higher security score = lower risk
                    security_score = 100 - risk_score
                    weekly_scores[weeks_ago].append(security_score)
            except:
                pass
        
        security_trend = []
        for week in range(7, -1, -1):  # Week 8 to Week 1
            scores = weekly_scores.get(week, [])
            avg_score = sum(scores) / len(scores) if scores else 50  # Default to 50 if no data
            security_trend.append({
                "week": f"Week {8-week}",
                "score": round(avg_score, 1)
            })
        
        analytics["security_trend"] = security_trend
        
        return analytics
        
    except Exception as e:
        print(f"[ANALYTICS ERROR] {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Analytics error: {str(e)}")
