#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         report_generator
# Purpose:      Generate visual reports and PDFs from SpiderFoot data
#
# Author:       Watchman8925
#
# Created:      2025
# License:      MIT
# -------------------------------------------------------------------------------

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

try:
    import matplotlib
    matplotlib.use('Agg')  # Use non-interactive backend
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (SimpleDocTemplate, Table, TableStyle,
                                     Paragraph, Spacer, PageBreak, Image)
    from reportlab.lib.enums import TA_CENTER
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False


class ReportGenerator:
    """Generate visual reports and PDF documents from SpiderFoot analysis."""

    def __init__(self, analysis_data: Dict[str, Any], output_dir: str = "./reports"):
        """
        Initialize the report generator.

        Args:
            analysis_data: Analysis results from SpiderFootAnalyzer
            output_dir: Directory to save reports (default: ./reports)
        """
        self.analysis_data = analysis_data
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.charts = []

    def generate_event_distribution_chart(self, output_path: Optional[str] = None) -> str:
        """
        Generate a pie chart of event type distribution.

        Args:
            output_path: Optional specific output path

        Returns:
            Path to the generated chart
        """
        if not HAS_MATPLOTLIB:
            raise ImportError("matplotlib is required for chart generation. Install with: pip install matplotlib")

        if output_path is None:
            output_path = self.output_dir / "event_distribution.png"

        event_dist = self.analysis_data.get('event_distribution', {})
        distribution = event_dist.get('distribution', {})

        if not distribution:
            return ""

        # Get top 10 event types and group others
        sorted_events = sorted(distribution.items(), key=lambda x: x[1], reverse=True)
        top_events = dict(sorted_events[:10])
        if len(sorted_events) > 10:
            others_count = sum([count for _, count in sorted_events[10:]])
            top_events['Others'] = others_count

        fig, ax = plt.subplots(figsize=(10, 6))
        colors_list = plt.cm.Set3(range(len(top_events)))

        wedges, texts, autotexts = ax.pie(
            top_events.values(),
            labels=top_events.keys(),
            autopct='%1.1f%%',
            colors=colors_list,
            startangle=90
        )

        ax.set_title('Event Type Distribution', fontsize=14, fontweight='bold')

        # Improve label readability
        for text in texts:
            text.set_fontsize(9)
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontsize(8)
            autotext.set_fontweight('bold')

        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()

        self.charts.append(str(output_path))
        return str(output_path)

    def generate_module_activity_chart(self, output_path: Optional[str] = None) -> str:
        """
        Generate a bar chart of module activity.

        Args:
            output_path: Optional specific output path

        Returns:
            Path to the generated chart
        """
        if not HAS_MATPLOTLIB:
            raise ImportError("matplotlib is required for chart generation")

        if output_path is None:
            output_path = self.output_dir / "module_activity.png"

        module_activity = self.analysis_data.get('module_activity', {})
        most_active = module_activity.get('most_active', [])

        if not most_active:
            return ""

        modules = [item[0] for item in most_active[:15]]
        counts = [item[1] for item in most_active[:15]]

        fig, ax = plt.subplots(figsize=(12, 6))
        bars = ax.barh(modules, counts, color='steelblue')

        ax.set_xlabel('Number of Events', fontsize=10)
        ax.set_title('Top Module Activity', fontsize=14, fontweight='bold')
        ax.invert_yaxis()

        # Add value labels on bars
        for bar in bars:
            width = bar.get_width()
            ax.text(width, bar.get_y() + bar.get_height()/2,
                   f' {int(width)}',
                   ha='left', va='center', fontsize=8)

        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()

        self.charts.append(str(output_path))
        return str(output_path)

    def generate_threat_overview_chart(self, output_path: Optional[str] = None) -> str:
        """
        Generate a bar chart showing corruption vs TOC indicators.

        Args:
            output_path: Optional specific output path

        Returns:
            Path to the generated chart
        """
        if not HAS_MATPLOTLIB:
            raise ImportError("matplotlib is required for chart generation")

        if output_path is None:
            output_path = self.output_dir / "threat_overview.png"

        corruption = self.analysis_data.get('corruption_patterns', {})
        toc = self.analysis_data.get('toc_patterns', {})
        risk_domains = self.analysis_data.get('risk_domains', {})
        compromised = self.analysis_data.get('compromised_assets', {})

        categories = ['Corruption\nIndicators', 'TOC\nIndicators',
                     'High-Risk\nDomains', 'Compromised\nAssets']
        values = [
            corruption.get('total_indicators', 0),
            toc.get('total_indicators', 0),
            risk_domains.get('total_risk_domains', 0),
            compromised.get('total_compromised', 0)
        ]

        fig, ax = plt.subplots(figsize=(10, 6))
        colors_list = ['#ff6b6b', '#feca57', '#ee5a6f', '#c44569']
        bars = ax.bar(categories, values, color=colors_list, edgecolor='black', linewidth=1.2)

        ax.set_ylabel('Count', fontsize=10)
        ax.set_title('Threat Overview', fontsize=14, fontweight='bold')
        ax.grid(axis='y', alpha=0.3)

        # Add value labels on top of bars
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2, height,
                   f'{int(height)}',
                   ha='center', va='bottom', fontsize=10, fontweight='bold')

        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()

        self.charts.append(str(output_path))
        return str(output_path)

    def generate_all_charts(self) -> List[str]:
        """
        Generate all available charts.

        Returns:
            List of paths to generated charts
        """
        charts = []

        try:
            chart = self.generate_event_distribution_chart()
            if chart:
                charts.append(chart)
        except Exception as e:
            print(f"Warning: Could not generate event distribution chart: {e}")

        try:
            chart = self.generate_module_activity_chart()
            if chart:
                charts.append(chart)
        except Exception as e:
            print(f"Warning: Could not generate module activity chart: {e}")

        try:
            chart = self.generate_threat_overview_chart()
            if chart:
                charts.append(chart)
        except Exception as e:
            print(f"Warning: Could not generate threat overview chart: {e}")

        return charts

    def generate_pdf_report(self, output_path: Optional[str] = None,
                           title: str = "SpiderFoot TOC/Corruption Analysis Report") -> str:
        """
        Generate a comprehensive PDF report.

        Args:
            output_path: Optional specific output path
            title: Report title

        Returns:
            Path to the generated PDF
        """
        if not HAS_REPORTLAB:
            raise ImportError("reportlab is required for PDF generation. Install with: pip install reportlab")

        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.output_dir / f"report_{timestamp}.pdf"

        # Generate charts first
        chart_paths = self.generate_all_charts()

        # Create PDF
        doc = SimpleDocTemplate(str(output_path), pagesize=letter)
        story = []
        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=30,
            alignment=TA_CENTER
        )

        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#34495e'),
            spaceAfter=12,
            spaceBefore=12
        )

        # Title page
        story.append(Paragraph(title, title_style))
        story.append(Spacer(1, 0.3*inch))

        # Report metadata
        metadata_text = f"""
        <b>Generated:</b> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br/>
        <b>Total Records:</b> {self.analysis_data.get('summary', {}).get('total_records', 0)}<br/>
        """
        story.append(Paragraph(metadata_text, styles['Normal']))
        story.append(Spacer(1, 0.5*inch))

        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))

        summary_data = self._generate_summary_table()
        if summary_data:
            summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(summary_table)
        story.append(PageBreak())

        # Charts section
        if chart_paths:
            story.append(Paragraph("Visual Analysis", heading_style))

            for chart_path in chart_paths:
                try:
                    img = Image(chart_path, width=6*inch, height=3.5*inch)
                    story.append(img)
                    story.append(Spacer(1, 0.3*inch))
                except Exception as e:
                    print(f"Warning: Could not add chart to PDF: {e}")

            story.append(PageBreak())

        # Detailed findings
        story.append(Paragraph("Detailed Findings", heading_style))
        story.append(self._generate_findings_content(styles))

        # Recommendations
        story.append(PageBreak())
        story.append(Paragraph("Recommendations", heading_style))
        story.append(self._generate_recommendations_content(styles))

        # Build PDF
        doc.build(story)
        return str(output_path)

    def _generate_summary_table(self) -> List[List[str]]:
        """Generate summary statistics table data."""
        event_dist = self.analysis_data.get('event_distribution', {})
        corruption = self.analysis_data.get('corruption_patterns', {})
        toc = self.analysis_data.get('toc_patterns', {})
        risk_domains = self.analysis_data.get('risk_domains', {})

        data = [
            ['Metric', 'Value'],
            ['Total Events', str(event_dist.get('total_events', 0))],
            ['Unique Event Types', str(event_dist.get('unique_event_types', 0))],
            ['Corruption Indicators', str(corruption.get('total_indicators', 0))],
            ['TOC Indicators', str(toc.get('total_indicators', 0))],
            ['High-Risk Domains', str(risk_domains.get('total_risk_domains', 0))]
        ]

        return data

    def _generate_findings_content(self, styles) -> Any:
        """Generate detailed findings content."""
        from reportlab.platypus import Paragraph

        corruption = self.analysis_data.get('corruption_patterns', {})
        toc = self.analysis_data.get('toc_patterns', {})

        content = f"""
        <b>Corruption Indicators:</b> {corruption.get('total_indicators', 0)} detected<br/>
        <b>Unique Keywords:</b> {corruption.get('unique_keywords', 0)}<br/>
        <br/>
        <b>TOC Indicators:</b> {toc.get('total_indicators', 0)} detected<br/>
        <b>Unique Keywords:</b> {toc.get('unique_keywords', 0)}<br/>
        """

        return Paragraph(content, styles['Normal'])

    def _generate_recommendations_content(self, styles) -> Any:
        """Generate recommendations content."""
        from reportlab.platypus import Paragraph
        from processor.analyzer import SpiderFootAnalyzer

        # Generate recommendations
        analyzer = SpiderFootAnalyzer([])  # Dummy for recommendations method
        analyzer.analysis_results = self.analysis_data

        # Get recommendations based on analysis
        recommendations = []

        corruption = self.analysis_data.get('corruption_patterns', {})
        if corruption.get('total_indicators', 0) > 10:
            recommendations.append(
                f"High number of corruption indicators detected ({corruption['total_indicators']}). "
                "Consider deeper investigation into identified entities."
            )

        toc = self.analysis_data.get('toc_patterns', {})
        if toc.get('total_indicators', 0) > 10:
            recommendations.append(
                f"Significant threat of compromise indicators found ({toc['total_indicators']}). "
                "Immediate security review recommended."
            )

        if not recommendations:
            recommendations.append("No significant threats detected. Continue monitoring.")

        content = "<br/>".join([f"• {rec}" for rec in recommendations])
        return Paragraph(content, styles['Normal'])

    def export_json_report(self, output_path: Optional[str] = None) -> str:
        """
        Export analysis results as JSON.

        Args:
            output_path: Optional specific output path

        Returns:
            Path to the JSON file
        """
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.output_dir / f"analysis_{timestamp}.json"

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.analysis_data, f, indent=2, default=str)

        return str(output_path)


def generate_report(analysis_data: Dict[str, Any], output_dir: str = "./reports",
                   generate_pdf: bool = True, generate_charts: bool = True) -> Dict[str, str]:
    """
    Convenience function to generate reports.

    Args:
        analysis_data: Analysis results from SpiderFootAnalyzer
        output_dir: Directory to save reports
        generate_pdf: Whether to generate PDF report
        generate_charts: Whether to generate charts

    Returns:
        Dictionary with paths to generated files
    """
    generator = ReportGenerator(analysis_data, output_dir)
    results = {}

    if generate_charts:
        try:
            charts = generator.generate_all_charts()
            results['charts'] = charts
        except ImportError as e:
            print(f"Warning: Could not generate charts: {e}")
            results['charts'] = []

    if generate_pdf:
        try:
            pdf_path = generator.generate_pdf_report()
            results['pdf'] = pdf_path
        except ImportError as e:
            print(f"Warning: Could not generate PDF: {e}")
            results['pdf'] = None

    # Always generate JSON
    json_path = generator.export_json_report()
    results['json'] = json_path

    return results
