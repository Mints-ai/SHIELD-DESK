-- Phase Q: Support Standalone Tasks without Mandatory Mitigation Plan
ALTER TABLE mitigation_tasks ALTER COLUMN plan_id DROP NOT NULL;
