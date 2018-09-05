package xades4j.utils;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;


import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.util.Strings;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;


/**
 * @author Artem R. Romanenko
 * @version 30.07.18
 */
public class RFC4519ExtensibleStyle extends RFC4519Style implements X500ExtensibleNameStyle
{
    private Map<String, String> keywordsMap;

    public RFC4519ExtensibleStyle()
    {
        updateKeyWordsMap();
    }

    @Override
    public void addSymbol(String oid, String... names)
    {
        ASN1ObjectIdentifier asn1ObjectIdentifier = new ASN1ObjectIdentifier(oid).intern();
        if(defaultSymbols.contains(asn1ObjectIdentifier))
        {
            throw new IllegalArgumentException("OID '" + oid + "' already registered");
        }
        for(String name : names){
            ASN1ObjectIdentifier exist = (ASN1ObjectIdentifier) defaultLookUp.get(Strings.toLowerCase(name));
            if(exist!=null)
            {
                throw new IllegalArgumentException("Name '" + name + "' already registered");
            }
        }
        boolean first = true;
        for(String name:names)
        {
            if(first)
            {
                defaultSymbols.put(asn1ObjectIdentifier, name);
                first = false;
            }
            defaultLookUp.put(name, asn1ObjectIdentifier);
        }
        updateKeyWordsMap();
    }

    private void updateKeyWordsMap()
    {
        Set<Map.Entry<String,ASN1ObjectIdentifier>> es = defaultLookUp.entrySet();
        Map<String, String> tmpMap = new HashMap<String, String>();
        for(Map.Entry<String,ASN1ObjectIdentifier> e : es){
            tmpMap.put(e.getKey().toUpperCase(), e.getValue().getId());
        }
        keywordsMap= Collections.unmodifiableMap(tmpMap);
    }
    @Override
    public Map<String,String> getKeywordMap()
    {
        return keywordsMap;
    }
}
