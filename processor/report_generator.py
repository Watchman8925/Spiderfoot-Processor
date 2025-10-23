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

try:
    from processor.llm_client import (
        LLMReportBuilder,
        LLMReportError,
        LLMReportResult,
    )
    HAS_LLM = True
except ImportError:  # Optional dependency
    LLMReportBuilder = None  # type: ignore
    LLMReportError = None  # type: ignore
    LLMReportResult = None  # type: ignore
    HAS_LLM = False


class ReportGenerator:
    """Generate visual reports and PDF documents from SpiderFoot analysis."""

    def __init__(
        self,
        analysis_data: Dict[str, Any],
        output_dir: str = "./reports",
        source_records: Optional[List[Dict[str, Any]]] = None,
        enable_llm: bool = True
    ):
        """
        Initialize the report generator.

        Args:
            analysis_data: Analysis results from SpiderFootAnalyzer
            output_dir: Directory to save reports (default: ./reports)
            source_records: Optional raw records to enrich AI narratives
            enable_llm: Whether to attempt LLM-assisted reporting
        """
        self.analysis_data = analysis_data
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.charts = []
        self.source_records = source_records or []
        self.enable_llm = enable_llm
        self._llm_builder = None
        self._llm_report = None
        self._llm_markdown_path = None
        self._llm_attempted = False
        self._llm_error = None

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

    def _ensure_llm_builder(self) -> Optional[Any]:
        """Initialise the LLM builder if configuration and dependencies permit."""
        if not self.enable_llm or not HAS_LLM:
            return None
        if self._llm_builder is not None:
            return self._llm_builder
        if self._llm_error:
            return None
        try:
            self._llm_builder = LLMReportBuilder.from_environment()
        except LLMReportError as exc:
            self._llm_error = str(exc)
            self.enable_llm = False
            print(f"  ! LLM reporting disabled: {exc}")
            self._llm_builder = None
        return self._llm_builder

    def _maybe_generate_llm_report(self) -> Optional[Any]:
        """Generate or retrieve a cached LLM narrative."""
        if self._llm_report is not None or self._llm_attempted:
            return self._llm_report

        self._llm_attempted = True

        builder = self._ensure_llm_builder()
        if builder is None:
            return None

        try:
            self._llm_report = builder.generate_report(self.analysis_data, self.source_records)
        except LLMReportError as exc:
            self._llm_error = str(exc)
            print(f"  ! AI narrative skipped: {exc}")
            self._llm_report = None
        except Exception as exc:
            self._llm_error = str(exc)
            print(f"  ! Unexpected error generating AI narrative: {exc}")
            self._llm_report = None

        return self._llm_report

    def _split_into_paragraphs(self, text: str) -> List[str]:
        """Split long-form text into digestible paragraphs for PDF layout."""
        if not text:
            return []
        normalized = text.replace('\r\n', '\n')
        blocks = [block.strip() for block in normalized.split('\n\n') if block.strip()]
        if not blocks:
            blocks = [normalized.strip()]
        return blocks

    def _build_llm_narrative_elements(
        self,
    llm_report: Any,
        body_style,
        section_heading_style
    ) -> List[Any]:
        """Convert LLM narrative into reportlab flowables."""
        elements: List[Any] = []

        elements.append(Paragraph("AI-Generated Executive Summary", section_heading_style))
        for paragraph in self._split_into_paragraphs(llm_report.executive_summary):
            elements.append(Paragraph(paragraph, body_style))
            elements.append(Spacer(1, 0.15*inch))

        if llm_report.narrative_sections:
            elements.append(Paragraph("Narrative Sections", section_heading_style))
            for idx, section in enumerate(llm_report.narrative_sections, start=1):
                title = section.get('title') or f"Section {idx}"
                elements.append(Paragraph(f"{idx}. {title}", section_heading_style))
                content = section.get('content') or section.get('body') or ''
                for paragraph in self._split_into_paragraphs(content):
                    elements.append(Paragraph(paragraph, body_style))
                    elements.append(Spacer(1, 0.12*inch))

        return elements

    def _build_pivots_section(
        self,
        pivots: List[Dict[str, Any]],
        body_style,
        section_heading_style,
        title: str = "Investigative Pivots & Leads"
    ) -> List[Any]:
        """Render pivots/leads into structured PDF content."""
        if not pivots:
            return []

        elements: List[Any] = [Paragraph(title, section_heading_style)]

        for pivot in pivots:
            name = pivot.get('title') or pivot.get('indicator') or 'Lead'
            confidence = pivot.get('confidence', 'Not rated')
            header = f"<b>{name}</b> — Confidence: {confidence}"
            elements.append(Paragraph(header, body_style))

            summary = pivot.get('summary') or ''
            for paragraph in self._split_into_paragraphs(summary):
                elements.append(Paragraph(paragraph, body_style))

            rationale = pivot.get('rationale') or ''
            if rationale and rationale != summary:
                elements.append(Paragraph(f"Rationale: {rationale}", body_style))

            recommendation = pivot.get('recommended_actions') or pivot.get('recommended_action')
            if recommendation:
                elements.append(Paragraph(f"Recommended Actions: {recommendation}", body_style))

            evidence = pivot.get('supporting_evidence') or []
            if evidence:
                evidence_text = '; '.join(evidence[:5])
                elements.append(Paragraph(f"Supporting Evidence: {evidence_text}", body_style))

            metrics = pivot.get('metrics') or {}
            if metrics:
                metric_pairs = ', '.join(f"{key}: {value}" for key, value in metrics.items())
                elements.append(Paragraph(f"Metrics: {metric_pairs}", body_style))

            elements.append(Spacer(1, 0.18*inch))

        return elements

    def export_llm_markdown(self, output_path: Optional[str] = None) -> Optional[str]:
        """Persist the LLM narrative as Markdown, if available."""
        llm_report = self._maybe_generate_llm_report()
        if not llm_report:
            return None

        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.output_dir / f"llm_narrative_{timestamp}.md"
        else:
            output_path = Path(output_path)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(llm_report.to_markdown(), encoding='utf-8')
        self._llm_markdown_path = str(output_path)
        return self._llm_markdown_path

    def get_llm_report_payload(self) -> Optional[Dict[str, Any]]:
        """Return the cached LLM report as a serialisable dictionary."""
        llm_report = self._maybe_generate_llm_report()
        if llm_report:
            return llm_report.to_dict()
        return None

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

        # Attempt to prepare AI narrative (non-blocking on failure)
        llm_report = self._maybe_generate_llm_report()

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
            textColor=colors.HexColor('#0f172a'),
            spaceAfter=30,
            alignment=TA_CENTER
        )

        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#0ea5e9'),
            spaceAfter=12,
            spaceBefore=12
        )

        body_style = ParagraphStyle(
            'CustomBody',
            parent=styles['BodyText'],
            fontSize=11,
            leading=14,
            spaceAfter=6
        )

        narrative_heading_style = ParagraphStyle(
            'NarrativeHeading',
            parent=styles['Heading3'],
            fontSize=13,
            textColor=colors.HexColor('#1e293b'),
            spaceBefore=10,
            spaceAfter=6
        )

        accent_header_color = colors.HexColor('#0f172a')
        accent_body_color = colors.HexColor('#d1fae5')

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
                ('BACKGROUND', (0, 0), (-1, 0), accent_header_color),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), accent_body_color),
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

        if llm_report:
            story.extend(self._build_llm_narrative_elements(llm_report, body_style, narrative_heading_style))
        else:
            story.append(self._generate_findings_content(styles))

        # Deterministic pivots from analysis
        pivots = self.analysis_data.get('pivots_and_leads', [])
        story.extend(self._build_pivots_section(pivots[:10], body_style, narrative_heading_style,
                                                title="Analytical Pivots & Leads"))

        # AI pivot enrichment
        if llm_report and llm_report.pivots_and_leads:
            ai_pivots = [lead.to_dict() for lead in llm_report.pivots_and_leads]
            story.extend(self._build_pivots_section(ai_pivots[:10], body_style, narrative_heading_style,
                                                    title="AI-Identified Strategic Leads"))

        # Recommendations
        story.append(PageBreak())
        story.append(Paragraph("Recommendations", heading_style))
        story.append(self._generate_recommendations_content(styles))

        if llm_report and llm_report.recommendations:
            story.append(Paragraph("AI Strategic Recommendations", narrative_heading_style))
            for recommendation in llm_report.recommendations:
                story.append(Paragraph(f"• {recommendation}", body_style))
            story.append(Spacer(1, 0.2*inch))

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
                   generate_pdf: bool = True, generate_charts: bool = True,
                   source_records: Optional[List[Dict[str, Any]]] = None,
                   enable_llm: bool = True) -> Dict[str, Any]:
    """
    Convenience function to generate reports.

    Args:
        analysis_data: Analysis results from SpiderFootAnalyzer
        output_dir: Directory to save reports
        generate_pdf: Whether to generate PDF report
        generate_charts: Whether to generate charts
        source_records: Optional raw records for richer AI narratives
        enable_llm: Whether to attempt LLM-assisted reporting

    Returns:
        Dictionary with generated artefact paths and optional AI payload
    """
    generator = ReportGenerator(
        analysis_data,
        output_dir,
        source_records=source_records,
        enable_llm=enable_llm
    )
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

    if enable_llm:
        llm_markdown = generator.export_llm_markdown()
        if llm_markdown:
            results['llm_markdown'] = llm_markdown
        llm_payload = generator.get_llm_report_payload()
        if llm_payload:
            results['llm_report'] = llm_payload

    return results
