아키텍처 상의 Admin Console(Front), Admin/Guardrail Backend, 그리고 Agent Backend의 흐름을 고려하여 역할을 분담했습니다.
아래 각 프로젝트를 폴더로 생성해서 작성해줘.

/agentic-ai-guardrail
|- admin-backend
|- admin-frontend
|- gateway-backend
ㄴ security-layer (빈 폴더로 비워두십시요 나중에 할껍니다.)

1. admin-backend 개발(2이 성공하면 그때 소스코드를 작성해)
 - Java: 17.0.14 + Spring Boot, java lint 사용, 
 - java-springboot 스킬을 반드시 사용하여 해당 원칙에 맞게 개발 진행.
 - tester가 작성한 실패하는 테스트 기반으로 테스트를 통과하는 함수를 작성하며 개발 진행.
 - 테스트가 완전히 통과할때 까지 수정.
2. admin-backend-tester (TTD)
 - Java: 17.0.14 + Spring Boot + Junit
 - spring-boot-testing 스킬을 반드시 사용하여 원칙에 맞게 개발.
 - tester는 developer의 개발에 전혀 관여 하지않음.
3. admin-frontend 개발 (4이 성공하면 그때 소스코드를 작성해)
 - React, typescript, SPA
4. admin-frontend-tester (TDD)
5. gateway-backend 개발 (5이 성공하면 그때 소스코드를 작성해)
 - Python: 3.11.11 + FastAPI, LangChain
6. gateway-backend-tester (TDD)
 - Python: 3.11.11