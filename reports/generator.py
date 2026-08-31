import logging
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape

import config
from core.models import Report

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate HTML reports from scan results."""

    def __init__(self, template_dir: Optional[str] = None):
        if template_dir is None:
            template_dir = str(Path(__file__).parent / "templates")
        
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )
        self.env.filters['sort'] = sorted

    def generate_html(self, report: Report, output_path: Optional[str] = None) -> str:
        """Generate HTML report from Report object."""
        template = self.env.get_template("report.html")
        report_dict = report.to_dict()
        if output_path:
            report_dict.setdefault("report_id", Path(output_path).stem.replace("report_", "").replace("scan_", ""))
        html_content = template.render(report=report_dict, report_id=report_dict.get("report_id"))
        
        if output_path:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info(f"HTML report saved to {output_path}")
            return str(output_file)
        
        return html_content

    def generate_from_dict(self, report_data: Dict[str, Any], 
                          output_path: Optional[str] = None) -> str:
        """Generate HTML report from dictionary."""
        template = self.env.get_template("report.html")
        if output_path:
            report_data.setdefault("report_id", Path(output_path).stem.replace("report_", "").replace("scan_", ""))
        html_content = template.render(report=report_data, report_id=report_data.get("report_id"))
        
        if output_path:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info(f"HTML report saved to {output_path}")
            return str(output_file)
        
        return html_content

    def generate_pdf(self, report_data: Dict[str, Any], output_path: str) -> str:
        """Generate a valid, professional PDF security assessment report using ReportLab."""
        import xml.sax.saxutils as saxutils
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.pdfgen import canvas

        class NumberedCanvas(canvas.Canvas):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._saved_page_states = []

            def showPage(self):
                self._saved_page_states.append(dict(self.__dict__))
                self._startPage()

            def save(self):
                num_pages = len(self._saved_page_states)
                for state in self._saved_page_states:
                    self.__dict__.update(state)
                    self.draw_page_number(num_pages)
                    canvas.Canvas.showPage(self)
                canvas.Canvas.save(self)

            def draw_page_number(self, page_count):
                self.saveState()
                self.setFont('Helvetica', 8)
                self.setFillColor(colors.HexColor('#64748B'))
                self.drawString(36, 25, 'CONFIDENTIAL — AutoSecAudit 2.0 Automated Penetration Testing Report')
                page_str = f'Page {self._pageNumber} of {page_count}'
                self.drawRightString(612 - 36, 25, page_str)
                self.setStrokeColor(colors.HexColor('#E2E8F0'))
                self.setLineWidth(0.5)
                self.line(36, 35, 612 - 36, 35)
                self.restoreState()

        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        target_name = str(report_data.get('target', 'Security Assessment'))
        doc = SimpleDocTemplate(
            str(output_file),
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=40,
            bottomMargin=45,
            title=f"AutoSecAudit Report - {target_name}",
            author="AutoSecAudit Security Framework"
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'ReportTitle',
            fontName='Helvetica-Bold',
            fontSize=18,
            leading=22,
            textColor=colors.HexColor('#0F172A')
        )
        sub_style = ParagraphStyle(
            'ReportSub',
            fontName='Helvetica',
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#475569')
        )
        h2_style = ParagraphStyle(
            'SectionHeader',
            fontName='Helvetica-Bold',
            fontSize=12,
            leading=16,
            textColor=colors.HexColor('#1E293B'),
            spaceBefore=10,
            spaceAfter=6
        )
        finding_title = ParagraphStyle(
            'FindingTitle',
            fontName='Helvetica-Bold',
            fontSize=10,
            leading=13,
            textColor=colors.HexColor('#FFFFFF')
        )
        finding_body = ParagraphStyle(
            'FindingBody',
            fontName='Helvetica',
            fontSize=8.5,
            leading=11.5,
            textColor=colors.HexColor('#334155')
        )
        remediation_style = ParagraphStyle(
            'RemediationText',
            fontName='Helvetica-Oblique',
            fontSize=8,
            leading=11,
            textColor=colors.HexColor('#1E1B4B')
        )

        story = []

        # Title & Metadata
        story.append(Paragraph('AutoSecAudit 2.0 — Executive Security Assessment', title_style))
        story.append(Spacer(1, 4))
        target_val = saxutils.escape(str(report_data.get('target', 'Unknown')))
        ts_val = saxutils.escape(str(report_data.get('timestamp', 'N/A')))
        story.append(Paragraph(f'<b>Target:</b> {target_val} &nbsp;|&nbsp; <b>Timestamp:</b> {ts_val}', sub_style))
        story.append(Spacer(1, 10))

        summary = report_data.get('summary', {})
        findings = report_data.get('all_findings', [])
        tot = summary.get('total', len(findings))
        crit = summary.get('critical', sum(1 for f in findings if str(f.get('severity', '')).lower() == 'critical'))
        high = summary.get('high', sum(1 for f in findings if str(f.get('severity', '')).lower() == 'high'))
        med = summary.get('medium', sum(1 for f in findings if str(f.get('severity', '')).lower() == 'medium'))
        low = summary.get('low', sum(1 for f in findings if str(f.get('severity', '')).lower() == 'low'))

        summary_data = [
            [
                Paragraph(f'<b>TOTAL FINDINGS</b><br/><font size="14"><b>{tot}</b></font>', sub_style),
                Paragraph(f'<font color="#DC2626"><b>CRITICAL</b></font><br/><font size="14" color="#DC2626"><b>{crit}</b></font>', sub_style),
                Paragraph(f'<font color="#EA580C"><b>HIGH</b></font><br/><font size="14" color="#EA580C"><b>{high}</b></font>', sub_style),
                Paragraph(f'<font color="#D97706"><b>MEDIUM</b></font><br/><font size="14" color="#D97706"><b>{med}</b></font>', sub_style),
                Paragraph(f'<font color="#16A34A"><b>LOW</b></font><br/><font size="14" color="#16A34A"><b>{low}</b></font>', sub_style),
            ]
        ]
        t = Table(summary_data, colWidths=[108, 108, 108, 108, 108])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(t)
        story.append(Spacer(1, 14))

        # Findings List
        story.append(Paragraph('Detailed Findings & Remediation Guidance', h2_style))
        story.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#CBD5E1'), spaceAfter=8))

        sev_colors = {
            'critical': colors.HexColor('#DC2626'),
            'high': colors.HexColor('#EA580C'),
            'medium': colors.HexColor('#D97706'),
            'low': colors.HexColor('#16A34A'),
            'info': colors.HexColor('#3B82F6'),
        }

        for idx, f in enumerate(findings, 1):
            sev = str(f.get('severity', 'info')).lower()
            sev_color = sev_colors.get(sev, colors.HexColor('#475569'))
            sev_text = sev.upper()
            title_text = saxutils.escape(str(f.get('title', 'Untitled Finding')))
            tool_text = saxutils.escape(str(f.get('tool_name', 'N/A')))
            owasp_text = saxutils.escape(str(f.get('owasp_tag', 'N/A')))
            cwe_text = saxutils.escape(str(f.get('cwe_id', 'N/A')))
            desc_raw = str(f.get('description', 'No description provided.'))
            desc_text = saxutils.escape(desc_raw).replace('\n', '<br/>')
            rem_raw = str(f.get('remediation', '') or '')
            rem_text = saxutils.escape(rem_raw).replace('\n', '<br/>') if rem_raw else ''

            header_table_data = [[
                Paragraph(f'<b>[{sev_text}] #{idx}: {title_text}</b>', finding_title),
            ]]
            ht = Table(header_table_data, colWidths=[540])
            ht.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), sev_color),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ]))

            meta_p = Paragraph(f'<b>Tool:</b> {tool_text} &nbsp;|&nbsp; <b>OWASP:</b> {owasp_text} &nbsp;|&nbsp; <b>CWE:</b> {cwe_text}', finding_body)
            desc_p = Paragraph(f'<b>Details:</b> {desc_text}', finding_body)

            card_elements = [ht, Spacer(1, 3), meta_p, Spacer(1, 3), desc_p]

            if rem_text:
                rem_p = Paragraph(f'<b>Remediation Advice:</b><br/>{rem_text}', remediation_style)
                rem_table = Table([[rem_p]], colWidths=[540])
                rem_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F1F5F9')),
                    ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ]))
                card_elements.extend([Spacer(1, 3), rem_table])

            card_elements.append(Spacer(1, 8))
            # Wrap in KeepTogether only if concise, otherwise allow natural flow
            if len(desc_raw) + len(rem_raw) < 1500:
                story.append(KeepTogether(card_elements))
            else:
                story.extend(card_elements)

        doc.build(story, canvasmaker=NumberedCanvas)
        logger.info(f"PDF report saved to {output_path}")
        return str(output_file)

    def generate_report(self, report: Report, 
                       previous_report: Optional[Report] = None) -> str:
        """Generate full report with optional delta comparison."""
        if previous_report:
            from intelligence.delta import DeltaAnalyzer
            delta_analyzer = DeltaAnalyzer()
            delta = delta_analyzer.compare(report, previous_report)
            report_data = report.to_dict()
            report_data["delta"] = delta
        else:
            report_data = report.to_dict()
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_data["report_id"] = timestamp
        output_path = f"{config.REPORTS_DIR}/report_{timestamp}.html"
        
        return self.generate_from_dict(report_data, output_path)

