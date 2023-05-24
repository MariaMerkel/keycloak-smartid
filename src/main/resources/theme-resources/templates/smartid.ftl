<#import "template.ftl" as layout>

<@layout.registrationLayout; section>
    <#if section = "form">
        <h1>Verification Code: ${verification_code}</h1>
        <p>Please ensure that the verification codes displayed here and in the Smart-ID app match and confirm your login via the app.</p>

        <form id="kc-smartid-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post"></form>
    </#if>
</@layout.registrationLayout>

<script type="application/javascript">
    document.getElementById('kc-smartid-login-form').submit();
</script>