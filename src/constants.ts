export type RuleConditionType = 'subject' | 'from' | 'to' | 'body' | 'header' | 'size' | 'spam_score';
export type RuleMatcher = 'contains' | 'is' | 'regex' | 'starts_with' | 'ends_with' | 'gt' | 'lt';
export type RuleActionType = 'move' | 'forward' | 'reject' | 'mark_read' | 'mark_spam' | 'add_flag';

export interface CustomRuleCondition {
  type: RuleConditionType;
  matcher: RuleMatcher;
  headerName?: string;
  value: string;
}

export interface CustomRuleAction {
  type: RuleActionType;
  value: string;
}

export interface CustomRule {
  id: string;
  name: string;
  active: boolean;
  condition: CustomRuleCondition;
  action: CustomRuleAction;
}

export const EMAIL_TAGS = [
  { keyword: '$label:red', name: '', color: 'bg-red-500' },
  { keyword: '$label:orange', name: '', color: 'bg-orange-500' },
  { keyword: '$label:yellow', name: '', color: 'bg-yellow-500' },
  { keyword: '$label:green', name: '', color: 'bg-green-500' },
  { keyword: '$label:blue', name: '', color: 'bg-blue-500' },
  { keyword: '$label:purple', name: '', color: 'bg-purple-500' },
  { keyword: '$label:pink', name: '', color: 'bg-pink-500' }
];
