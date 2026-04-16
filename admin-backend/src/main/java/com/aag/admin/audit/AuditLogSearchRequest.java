package com.aag.admin.audit;

public class AuditLogSearchRequest {

    private int page = 0;
    private int size = 20;
    private String from;
    private String to;
    private String actionId;
    private String action;
    private Boolean success;
    private String sort = "occurredAt";
    private String direction = "desc";

    public int getPage() { return page; }
    public void setPage(int page) { this.page = page; }
    public int getSize() { return size; }
    public void setSize(int size) { this.size = size; }
    public String getFrom() { return from; }
    public void setFrom(String from) { this.from = from; }
    public String getTo() { return to; }
    public void setTo(String to) { this.to = to; }
    public String getActionId() { return actionId; }
    public void setActionId(String actionId) { this.actionId = actionId; }
    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }
    public Boolean getSuccess() { return success; }
    public void setSuccess(Boolean success) { this.success = success; }
    public String getSort() { return sort; }
    public void setSort(String sort) { this.sort = sort; }
    public String getDirection() { return direction; }
    public void setDirection(String direction) { this.direction = direction; }
}
