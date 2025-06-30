#!/usr/bin/env node

import { Command } from 'commander';
import fs from 'fs/promises';
import chalk from 'chalk';

const program = new Command();

program
  .name('check-compliance')
  .description('Check compliance against security frameworks')
  .version('1.0.0')
  .requiredOption('--audit-file <file>', 'Audit results JSON file')
  .option('--frameworks <frameworks>', 'Frameworks to check (comma-separated)', 'OWASP,NIST,ISO27001')
  .option('--output <file>', 'Output compliance report file')
  .parse();

const options = program.opts();

// Compliance framework mappings
const COMPLIANCE_FRAMEWORKS = {
  OWASP: {
    name: 'OWASP Top 10 2021',
    controls: {
      'A01:2021 – Broken Access Control': {
        weight: 10,
        checks: [
          { type: 'code', pattern: /auth|authorization|access/i, weight: 5 },
          { type: 'feature', name: 'branchProtection', weight: 3 },
          { type: 'alert', severity: ['critical', 'high'], category: 'access', weight: 2 }
        ]
      },
      'A02:2021 – Cryptographic Failures': {
        weight: 10,
        checks: [
          { type: 'secret', pattern: /key|token|password/i, weight: 5 },
          { type: 'code', pattern: /crypto|encrypt|hash/i, weight: 3 },
          { type: 'dependency', packages: ['crypto', 'bcrypt'], weight: 2 }
        ]
      },
      'A03:2021 – Injection': {
        weight: 10,
        checks: [
          { type: 'code', pattern: /injection|sql|xss|cmd/i, weight: 7 },
          { type: 'alert', severity: ['critical', 'high'], category: 'injection', weight: 3 }
        ]
      },
      'A04:2021 – Insecure Design': {
        weight: 8,
        checks: [
          { type: 'feature', name: 'codeScanning', weight: 4 },
          { type: 'feature', name: 'secretScanning', weight: 4 }
        ]
      },
      'A05:2021 – Security Misconfiguration': {
        weight: 8,
        checks: [
          { type: 'feature', name: 'branchProtection', weight: 4 },
          { type: 'code', pattern: /config|setup|init/i, weight: 2 },
          { type: 'alert', severity: ['medium', 'high'], category: 'config', weight: 2 }
        ]
      },
      'A06:2021 – Vulnerable Components': {
        weight: 9,
        checks: [
          { type: 'dependency', outdated: true, weight: 7 },
          { type: 'feature', name: 'dependabot', weight: 2 }
        ]
      },
      'A07:2021 – Authentication Failures': {
        weight: 7,
        checks: [
          { type: 'code', pattern: /login|auth|session/i, weight: 4 },
          { type: 'secret', pattern: /session|jwt|auth/i, weight: 3 }
        ]
      },
      'A08:2021 – Software Integrity Failures': {
        weight: 6,
        checks: [
          { type: 'feature', name: 'codeScanning', weight: 3 },
          { type: 'dependency', verified: true, weight: 3 }
        ]
      },
      'A09:2021 – Logging Failures': {
        weight: 5,
        checks: [
          { type: 'code', pattern: /log|audit|monitor/i, weight: 3 },
          { type: 'secret', pattern: /log|trace/i, weight: 2 }
        ]
      },
      'A10:2021 – Server-Side Request Forgery': {
        weight: 5,
        checks: [
          { type: 'code', pattern: /ssrf|request|fetch/i, weight: 3 },
          { type: 'alert', severity: ['high'], category: 'ssrf', weight: 2 }
        ]
      }
    }
  },
  
  NIST: {
    name: 'NIST Cybersecurity Framework',
    controls: {
      'Identify (ID)': {
        weight: 20,
        checks: [
          { type: 'repository', count: true, weight: 10 },
          { type: 'feature', name: 'scanning', weight: 10 }
        ]
      },
      'Protect (PR)': {
        weight: 25,
        checks: [
          { type: 'feature', name: 'branchProtection', weight: 8 },
          { type: 'feature', name: 'secretScanning', weight: 8 },
          { type: 'dependency', current: true, weight: 9 }
        ]
      },
      'Detect (DE)': {
        weight: 25,
        checks: [
          { type: 'feature', name: 'codeScanning', weight: 10 },
          { type: 'feature', name: 'secretScanning', weight: 8 },
          { type: 'feature', name: 'dependabot', weight: 7 }
        ]
      },
      'Respond (RS)': {
        weight: 15,
        checks: [
          { type: 'metric', name: 'meanTimeToResolve', threshold: 30, weight: 8 },
          { type: 'alert', state: 'open', weight: 7 }
        ]
      },
      'Recover (RC)': {
        weight: 15,
        checks: [
          { type: 'process', name: 'audit', weight: 8 },
          { type: 'documentation', exists: true, weight: 7 }
        ]
      }
    }
  },
  
  ISO27001: {
    name: 'ISO 27001:2022',
    controls: {
      'A.5 Information Security Policies': {
        weight: 5,
        checks: [
          { type: 'documentation', policy: true, weight: 5 }
        ]
      },
      'A.8 Asset Management': {
        weight: 10,
        checks: [
          { type: 'repository', inventory: true, weight: 10 }
        ]
      },
      'A.12 Operations Security': {
        weight: 15,
        checks: [
          { type: 'feature', name: 'codeScanning', weight: 5 },
          { type: 'feature', name: 'secretScanning', weight: 5 },
          { type: 'process', name: 'monitoring', weight: 5 }
        ]
      },
      'A.13 Communications Security': {
        weight: 10,
        checks: [
          { type: 'secret', encrypted: true, weight: 5 },
          { type: 'code', pattern: /tls|ssl|https/i, weight: 5 }
        ]
      },
      'A.14 System Development': {
        weight: 20,
        checks: [
          { type: 'feature', name: 'codeScanning', weight: 7 },
          { type: 'feature', name: 'branchProtection', weight: 6 },
          { type: 'process', name: 'secureSDLC', weight: 7 }
        ]
      },
      'A.16 Information Security Incident Management': {
        weight: 15,
        checks: [
          { type: 'alert', response: true, weight: 8 },
          { type: 'metric', name: 'responseTime', weight: 7 }
        ]
      },
      'A.17 Business Continuity': {
        weight: 10,
        checks: [
          { type: 'backup', exists: true, weight: 5 },
          { type: 'process', name: 'recovery', weight: 5 }
        ]
      },
      'A.18 Compliance': {
        weight: 15,
        checks: [
          { type: 'audit', regular: true, weight: 8 },
          { type: 'documentation', compliance: true, weight: 7 }
        ]
      }
    }
  }
};

async function checkCompliance() {
  try {
    // Read audit results
    const auditData = JSON.parse(await fs.readFile(options.auditFile, 'utf8'));
    
    // Parse frameworks to check
    const frameworksToCheck = options.frameworks.split(',').map(f => f.trim());
    
    const complianceReport = {
      metadata: {
        auditFile: options.auditFile,
        frameworks: frameworksToCheck,
        checkDate: new Date().toISOString(),
        version: '1.0.0'
      },
      results: {},
      summary: {
        overallScore: 0,
        frameworkScores: {},
        recommendations: []
      }
    };
    
    // Check each framework
    for (const frameworkCode of frameworksToCheck) {
      if (COMPLIANCE_FRAMEWORKS[frameworkCode]) {
        const result = await checkFramework(frameworkCode, auditData);
        complianceReport.results[frameworkCode] = result;
        complianceReport.summary.frameworkScores[frameworkCode] = result.overallScore;
      }
    }
    
    // Calculate overall score
    const scores = Object.values(complianceReport.summary.frameworkScores);
    complianceReport.summary.overallScore = scores.reduce((a, b) => a + b, 0) / scores.length;
    
    // Generate recommendations
    complianceReport.summary.recommendations = generateRecommendations(complianceReport);
    
    // Output results
    if (options.output) {
      await fs.writeFile(options.output, JSON.stringify(complianceReport, null, 2));
      console.log(chalk.green(`✅ Compliance report saved to: ${options.output}`));
    }
    
    // Print summary
    printComplianceSummary(complianceReport);
    
  } catch (error) {
    console.error(chalk.red('Error checking compliance:'), error.message);
    process.exit(1);
  }
}

async function checkFramework(frameworkCode, auditData) {
  const framework = COMPLIANCE_FRAMEWORKS[frameworkCode];
  const result = {
    name: framework.name,
    overallScore: 0,
    controlScores: {},
    details: {},
    gaps: []
  };
  
  let totalWeight = 0;
  let weightedScore = 0;
  
  for (const [controlName, control] of Object.entries(framework.controls)) {
    const controlScore = checkControl(control, auditData);
    result.controlScores[controlName] = controlScore;
    
    totalWeight += control.weight;
    weightedScore += (controlScore.score * control.weight);
    
    if (controlScore.score < 70) {
      result.gaps.push({
        control: controlName,
        score: controlScore.score,
        issues: controlScore.issues
      });
    }
  }
  
  result.overallScore = totalWeight > 0 ? (weightedScore / totalWeight) : 0;
  
  return result;
}

function checkControl(control, auditData) {
  const score = {
    score: 0,
    maxScore: 0,
    details: [],
    issues: []
  };
  
  for (const check of control.checks) {
    const checkResult = evaluateCheck(check, auditData);
    score.score += checkResult.score;
    score.maxScore += check.weight;
    score.details.push(checkResult);
    
    if (checkResult.score < check.weight * 0.7) {
      score.issues.push(checkResult.issue);
    }
  }
  
  score.score = score.maxScore > 0 ? (score.score / score.maxScore) * 100 : 0;
  
  return score;
}

function evaluateCheck(check, auditData) {
  const result = {
    type: check.type,
    score: 0,
    maxScore: check.weight,
    issue: null
  };
  
  switch (check.type) {
    case 'feature':
      result.score = evaluateSecurityFeature(check, auditData);
      if (result.score < check.weight * 0.7) {
        result.issue = `Security feature '${check.name}' not adequately enabled`;
      }
      break;
      
    case 'code':
      result.score = evaluateCodePatterns(check, auditData);
      if (result.score < check.weight * 0.7) {
        result.issue = `Code patterns for '${check.pattern}' need attention`;
      }
      break;
      
    case 'secret':
      result.score = evaluateSecretScanning(check, auditData);
      if (result.score < check.weight * 0.7) {
        result.issue = `Secret scanning alerts found for '${check.pattern}'`;
      }
      break;
      
    case 'dependency':
      result.score = evaluateDependencies(check, auditData);
      if (result.score < check.weight * 0.7) {
        result.issue = 'Dependency vulnerabilities need attention';
      }
      break;
      
    case 'alert':
      result.score = evaluateAlerts(check, auditData);
      if (result.score < check.weight * 0.7) {
        result.issue = `${check.severity.join('/')} severity alerts need resolution`;
      }
      break;
      
    case 'metric':
      result.score = evaluateMetrics(check, auditData);
      if (result.score < check.weight * 0.7) {
        result.issue = `Metric '${check.name}' exceeds threshold`;
      }
      break;
      
    default:
      result.score = check.weight * 0.5; // Default partial score
      result.issue = `Check type '${check.type}' not implemented`;
  }
  
  return result;
}

function evaluateSecurityFeature(check, auditData) {
  const repos = auditData.repositories;
  if (repos.length === 0) return 0;
  
  let enabledCount = 0;
  
  repos.forEach(repo => {
    switch (check.name) {
      case 'codeScanning':
        if (repo.securityFeatures.codeScanning.enabled) enabledCount++;
        break;
      case 'secretScanning':
        if (repo.securityFeatures.secretScanning.enabled) enabledCount++;
        break;
      case 'dependabot':
        if (repo.securityFeatures.dependabot.enabled) enabledCount++;
        break;
      case 'branchProtection':
        if (repo.securityFeatures.branchProtection.enabled) enabledCount++;
        break;
      case 'scanning':
        if (repo.securityFeatures.codeScanning.enabled && 
            repo.securityFeatures.secretScanning.enabled &&
            repo.securityFeatures.dependabot.enabled) enabledCount++;
        break;
    }
  });
  
  const percentage = (enabledCount / repos.length) * 100;
  return (percentage / 100) * check.weight;
}

function evaluateCodePatterns(check, auditData) {
  const codeAlerts = auditData.repositories.reduce((acc, repo) => 
    acc.concat(repo.alerts.code), []
  );
  
  const patternMatches = codeAlerts.filter(alert => 
    check.pattern.test(alert.rule + ' ' + alert.description)
  ).length;
  
  // Lower pattern matches = better score
  if (patternMatches === 0) return check.weight;
  if (patternMatches < 5) return check.weight * 0.7;
  if (patternMatches < 10) return check.weight * 0.4;
  return check.weight * 0.2;
}

function evaluateSecretScanning(check, auditData) {
  const secretAlerts = auditData.repositories.reduce((acc, repo) => 
    acc.concat(repo.alerts.secret), []
  );
  
  const patternMatches = secretAlerts.filter(alert => 
    check.pattern.test(alert.secretType + ' ' + alert.secretTypeDisplayName)
  ).length;
  
  // Lower secret alerts = better score
  if (patternMatches === 0) return check.weight;
  if (patternMatches < 3) return check.weight * 0.6;
  return check.weight * 0.2;
}

function evaluateDependencies(check, auditData) {
  const dependencyAlerts = auditData.repositories.reduce((acc, repo) => 
    acc.concat(repo.alerts.dependency), []
  );
  
  if (check.outdated) {
    // Check for outdated dependencies
    const outdatedCount = dependencyAlerts.length;
    if (outdatedCount === 0) return check.weight;
    if (outdatedCount < 10) return check.weight * 0.7;
    if (outdatedCount < 25) return check.weight * 0.4;
    return check.weight * 0.2;
  }
  
  return check.weight * 0.5; // Default score
}

function evaluateAlerts(check, auditData) {
  const allAlerts = auditData.repositories.reduce((acc, repo) => {
    return acc.concat(repo.alerts.code, repo.alerts.secret, repo.alerts.dependency);
  }, []);
  
  const matchingAlerts = allAlerts.filter(alert => {
    if (check.severity) {
      return check.severity.includes(alert.severity?.toLowerCase());
    }
    return alert.state === check.state;
  }).length;
  
  // Lower alert count = better score
  if (matchingAlerts === 0) return check.weight;
  if (matchingAlerts < 5) return check.weight * 0.8;
  if (matchingAlerts < 15) return check.weight * 0.5;
  return check.weight * 0.2;
}

function evaluateMetrics(check, auditData) {
  const repos = auditData.repositories;
  if (repos.length === 0) return 0;
  
  switch (check.name) {
    case 'meanTimeToResolve':
      const avgMTTR = repos.reduce((sum, repo) => 
        sum + repo.metrics.meanTimeToResolve, 0
      ) / repos.length;
      
      if (avgMTTR <= check.threshold) return check.weight;
      if (avgMTTR <= check.threshold * 2) return check.weight * 0.6;
      return check.weight * 0.2;
      
    default:
      return check.weight * 0.5;
  }
}

function generateRecommendations(complianceReport) {
  const recommendations = [];
  
  // High-level recommendations based on overall scores
  for (const [framework, score] of Object.entries(complianceReport.summary.frameworkScores)) {
    if (score < 60) {
      recommendations.push({
        priority: 'High',
        framework,
        title: `Improve ${framework} Compliance`,
        description: `Current score (${score.toFixed(1)}%) is below target threshold`,
        actions: getFrameworkRecommendations(framework, complianceReport.results[framework])
      });
    } else if (score < 80) {
      recommendations.push({
        priority: 'Medium',
        framework,
        title: `Enhance ${framework} Controls`,
        description: `Score (${score.toFixed(1)}%) has room for improvement`,
        actions: getFrameworkRecommendations(framework, complianceReport.results[framework])
      });
    }
  }
  
  return recommendations;
}

function getFrameworkRecommendations(framework, result) {
  const actions = [];
  
  result.gaps.forEach(gap => {
    actions.push(`Address gaps in ${gap.control} (Score: ${gap.score.toFixed(1)}%)`);
    gap.issues.forEach(issue => {
      if (issue) actions.push(`- ${issue}`);
    });
  });
  
  return actions.slice(0, 5); // Limit to top 5 actions
}

function printComplianceSummary(report) {
  console.log(chalk.blue.bold('\n📋 Compliance Check Summary\n'));
  
  console.log(`Overall Compliance Score: ${chalk.bold(report.summary.overallScore.toFixed(1))}%`);
  
  console.log('\nFramework Scores:');
  for (const [framework, score] of Object.entries(report.summary.frameworkScores)) {
    const color = score >= 80 ? chalk.green : score >= 60 ? chalk.yellow : chalk.red;
    console.log(`  ${framework}: ${color(score.toFixed(1))}%`);
  }
  
  if (report.summary.recommendations.length > 0) {
    console.log(chalk.yellow('\n⚠️  Recommendations:'));
    report.summary.recommendations.forEach((rec, index) => {
      console.log(`${index + 1}. ${rec.title} (${rec.priority} Priority)`);
      console.log(`   ${rec.description}`);
    });
  }
  
  console.log(chalk.green('\n✅ Compliance check completed'));
}

// Run compliance check
checkCompliance();