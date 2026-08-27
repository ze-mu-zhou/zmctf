/***************************************************************************
 * Bytecode Viewer (BCV) - Java & Android Reverse Engineering Suite        *
 * Copyright (C) 2014 Konloch - Konloch.com / BytecodeViewer.com           *
 *                                                                         *
 * This program is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation, either version 3 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 ***************************************************************************/

package the.bytecode.club.bytecodeviewer.translation;

import com.google.gson.reflect.TypeToken;
import org.apache.commons.collections4.map.LinkedMap;
import the.bytecode.club.bytecodeviewer.BytecodeViewer;
import the.bytecode.club.bytecodeviewer.api.BCV;
import the.bytecode.club.bytecodeviewer.resources.Resource;

import java.io.IOException;
import java.util.*;

/**
 * All of the supported languages
 * <p>
 * This fork only ships English (internal fallback) and Mandarin.
 *
 * @author Konloch
 * @since 6/28/2021
 */
public enum Language
{
    ENGLISH("/translations/english.json", "English", "English", "en"),
    MANDARIN("/translations/mandarin.json", "普通话", "Mandarin", "zh-CN", "zh_cn", "zh"),
    ;

    private static final Map<String, Language> languageCodeLookup;

    static
    {
        languageCodeLookup = new LinkedHashMap<>();
        for(Language l : values())
            l.languageCode.forEach((langCode)->
                languageCodeLookup.put(langCode, l));
    }

    private final String resourcePath;
    private final String readableName;
    private final String htmlIdentifier;
    private final Set<String> languageCode;
    private Map<String, String> translationMap;

    Language(String resourcePath, String readableName, String htmlIdentifier, String... languageCodes)
    {
        this.resourcePath = resourcePath;
        this.readableName = readableName;
        this.htmlIdentifier = htmlIdentifier.toLowerCase();
        this.languageCode = new LinkedHashSet<>(Arrays.asList(languageCodes));
    }

    public void setLanguageTranslations() throws IOException
    {
        printMissingLanguageKeys();

        Map<String, String> translationMap = getTranslation();

        for(TranslatedComponents translatedComponents : TranslatedComponents.values())
        {
            TranslatedComponentReference text = translatedComponents.getTranslatedComponentReference();

            //skip translating if the language config is missing the translation key
            if(!translationMap.containsKey(text.key))
            {
                BCV.logE(true, resourcePath + " -> " + text.key + " - Missing Translation Key");
                continue;
            }

            //update translation text value
            text.value = translationMap.get(text.key);

            //translate constant strings
            try {
                TranslatedStrings str = TranslatedStrings.valueOf(text.key);
                str.setText(text.value);
            } catch (IllegalArgumentException ignored) { }

            //check if translation key has been assigned to a component,
            //on fail print an error alerting the devs
            if(translatedComponents.getTranslatedComponentReference().runOnUpdate.isEmpty())
            //&& TranslatedStrings.nameSet.contains(translation.name()))
            {
                BCV.logE(true, "TranslatedComponents:" + translatedComponents.name() + " is missing component attachment, skipping...");
                continue;
            }

            //trigger translation event
            translatedComponents.getTranslatedComponentReference().translate();
        }
    }

    public Map<String, String> getTranslation() throws IOException
    {
        if(translationMap == null)
        {
            translationMap = BytecodeViewer.gson.fromJson(
                Resource.loadResourceAsString(resourcePath),
                new TypeToken<HashMap<String, String>>() {}.getType());
        }

        return translationMap;
    }

    //TODO
    // When adding new Translation Components:
    // 1) start by adding the strings into the english.json
    // 2) run this function to get the keys and add them into the Translation.java enum
    // 3) replace the swing component (MainViewerGUI) with a translated component
    //    and reference the correct translation key
    // 4) add the translation key to the rest of the translation files
    public void printMissingLanguageKeys() throws IOException
    {
        if(this != ENGLISH)
            return;

        LinkedMap<String, String> translationMap = BytecodeViewer.gson.fromJson(
            Resource.loadResourceAsString(resourcePath),
            new TypeToken<LinkedMap<String, String>>(){}.getType());

        Set<String> existingKeys = new HashSet<>();
        for(TranslatedComponents t : TranslatedComponents.values())
            existingKeys.add(t.name());

        for(String key : translationMap.keySet())
            if(!existingKeys.contains(key))
                BCV.logE(true, key + ",");
    }

    public String getResourcePath()
    {
        return resourcePath;
    }

    public Set<String> getLanguageCode()
    {
        return languageCode;
    }

    public String getReadableName()
    {
        return readableName;
    }

    public String getHTMLPath(String identifier)
    {
        return "translations/html/" + identifier + "." + htmlIdentifier +  ".html";
    }

    public static Map<String, Language> getLanguageCodeLookup()
    {
        return languageCodeLookup;
    }
}
