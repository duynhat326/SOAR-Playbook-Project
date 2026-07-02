# SOAR Playbook Upgrade Roadmap

## Muc tieu nang cap

Project hien tai da co loi xu ly tot cho demo:

- schema ro rang voi Pydantic
- enrichment pipeline tach module
- policy engine theo rule
- dashboard Streamlit
- output report va mock actions

Muc tieu cua ban nang cap nay la bien repo tu "demo pipeline" thanh "nen tang SOAR co the mo rong", theo thu tu uu tien:

1. chuan hoa orchestration layer de CLI, dashboard va API dung chung mot luong
2. them API service de co the nhan webhook va tich hop ben ngoai
3. them persistence co cau truc thay cho file JSON roi rac
4. tach policy thanh du lieu cau hinh thay vi hardcode
5. them background workers, correlation va analyst workflow
6. thay mock adapters bang integration that

## Nguyen tac thuc hien

- moi phase phai tao ra gia tri su dung duoc
- uu tien thay doi co the gop dan, tranh viet lai toan bo
- giu backward compatibility cho CLI va dashboard trong cac phase dau
- bat dau bang service layer dung lai cac module tot san co

## Phase 0 - Baseline va khoa no ky thuat

Trang thai: dang thuc hien

Muc tieu:

- ghi lai lo trinh nang cap ro rang
- co service orchestration trung tam
- xac dinh cac entrypoint moi se dung chung service do

Cong viec:

- [x] danh gia kien truc hien tai
- [x] chon lo trinh nang cap
- [x] viet file roadmap trong repo
- [x] tach orchestration layer thanh service tai su dung duoc
- [x] noi `main.py` va `dashboard/app.py` vao service moi

Tieu chi hoan thanh:

- khong con logic enrich -> policy -> report bi lap lai o nhieu entrypoint

## Phase 1 - API Service

Trang thai: dang thuc hien

Muc tieu:

- them REST API de trigger pipeline
- tao hop dong request/response on dinh cho tich hop tu EDR, SIEM, webhook

Cong viec:

- [x] them package `api/`
- [x] them `FastAPI` va `uvicorn` vao dependencies
- [x] tao endpoint `GET /health`
- [x] tao endpoint `POST /api/v1/incidents/process`
- [x] tao endpoint `POST /api/v1/incidents/process-scenario`
- [x] dung chung service orchestration thay vi goi truc tiep pipeline trong route
- [ ] tai lieu hoa cach chay API

Tieu chi hoan thanh:

- co the gui mot `MalwareAlert` hop le qua HTTP va nhan `IncidentResponse`
- co the goi theo scenario cho demo nhanh

## Phase 2 - Persistence Layer

Trang thai: chua bat dau

Muc tieu:

- thay output file tam bang persistence co cau truc
- co lich su incident, action, artifact va audit trail

Cong viec:

- [x] tao `storage/` hoac `repositories/`
- [x] chon SQLite lam buoc dau, sau do mo duong sang Postgres
- [x] tao bang `alerts`
- [x] tao bang `incidents`
- [x] tao bang `action_results`
- [x] tao bang `reports`
- [x] luu du lieu ngay sau khi pipeline chay xong
- [ ] them idempotency key de tranh tao ticket trung khi webhook gui lai

Tieu chi hoan thanh:

- incident co the duoc truy van lai bang `alert_id` hoac `ticket_id`
- khong phu thuoc vao `output/*.json` de xac dinh state chinh

## Phase 3 - Policy as Data

Trang thai: chua bat dau

Muc tieu:

- dua rules ra khoi code hardcoded
- cho phep bat/tat rule, sua threshold ma khong can deploy lai code

Cong viec:

- [x] tao `policies/response_rules.yaml`
- [x] dinh nghia schema cho rule
- [x] viet policy loader + validator
- [x] doi `engine/policy_engine.py` sang evaluate theo rule config
- [ ] ho tro severity threshold, asset threshold, allowlist, denylist
- [x] them fallback khi file policy loi

Tieu chi hoan thanh:

- thay doi rule co the thuc hien bang config
- policy engine van tra ve reasoning ro rang

## Phase 4 - Real Integrations

Trang thai: chua bat dau

Muc tieu:

- thay mock intel va mock action bang adapter that theo tung lop

Cong viec:

- [ ] them config env cho API keys
- [ ] them `VirusTotalHashIntel`
- [ ] them `AbuseIPDBIntel` hoac `OTXIntel`
- [ ] them `ServiceNowCMDB` hoac adapter CMDB bat ky
- [ ] them ticketing adapter that nhu TheHive, Jira hoac ServiceNow
- [ ] them che do fallback mock/degraded mode
- [ ] them retry, timeout, rate-limit va observability cho adapter

Tieu chi hoan thanh:

- co the chon adapter qua config
- loi integration khong lam sap toan bo pipeline

## Phase 5 - Analyst Experience

Trang thai: chua bat dau

Muc tieu:

- nang dashboard thanh analyst console
- theo doi incident va ra quyet dinh ban tu dong

Cong viec:

- [ ] hien queue incident
- [ ] filter theo risk level, host, user, action
- [ ] trang chi tiet incident
- [ ] hien reasoning cua tung policy
- [ ] nut approve/reject cho cac action nguy hiem
- [ ] lich su xu ly theo host va user

Tieu chi hoan thanh:

- analyst co the xem, xac nhan, va theo doi incident trong mot giao dien duy nhat

## Phase 6 - Correlation va Asynchronous Execution

Trang thai: chua bat dau

Muc tieu:

- xu ly duoc alert volume lon va tranh trung incident

Cong viec:

- [ ] bo sung worker queue
- [ ] tach ingestion khoi execution
- [ ] them correlation theo `hostname`, `username`, `file_hash`, `destination_ip`
- [ ] gom nhieu alert vao mot incident cha
- [ ] them retry queue cho action that
- [ ] them dead-letter queue

Tieu chi hoan thanh:

- nhieu alert lien quan khong tao ra nhieu ticket trung
- pipeline co the chay bat dong bo va theo doi trang thai

## Thu tu thuc hien de xuat

1. Hoan thanh service layer va API scaffold.
2. Dua persistence vao service/API.
3. Chuyen policy sang config.
4. Chon 1 adapter intel that va 1 adapter ticketing that.
5. Nang dashboard va worker/correlation.

## Hang muc dang lam ngay bay gio

Trong lan cap nhat nay, muc tieu la:

- tao roadmap nay
- tao service orchestration dung chung
- scaffold FastAPI API
- cap nhat CLI va dashboard de dung service moi
